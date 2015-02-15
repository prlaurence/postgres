/*
 * pg_audit/pg_audit.c
 *
 * An auditing extension for PostgreSQL. Improves on standard statement logging
 * by adding more logging classes, object level logging, and providing
 * fully-qualified object names for all DML and many DDL statements.
 *
 *
 * Copyright © 2014-2015, PostgreSQL Global Development Group
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose, without fee, and without a
 * written agreement is hereby granted, provided that the above
 * copyright notice and this paragraph and the following two
 * paragraphs appear in all copies.
 *
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE TO ANY PARTY FOR DIRECT,
 * INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
 * DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE AUTHOR SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS
 * IS" BASIS, AND THE AUTHOR HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE,
 * SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 */
#include "postgres.h"

#include "access/htup_details.h"
#include "access/sysattr.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_class.h"
#include "catalog/namespace.h"
#include "commands/dbcommands.h"
#include "catalog/pg_proc.h"
#include "commands/event_trigger.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "libpq/auth.h"
#include "nodes/nodes.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/timestamp.h"

PG_MODULE_MAGIC;

void _PG_init(void);

/*
 * auditRole is the string value of the pgaudit.role GUC, which contains the
 * role for grant-based auditing.
 */
char *auditRole = NULL;

/*
 * auditLog is the string value of the pgaudit.log GUC, e.g. "read, write, ddl"
 * (it's not used by the module but is required by DefineCustomStringVariable).
 * Each token corresponds to a flag in enum LogClass below. We convert the list
 * of tokens into a bitmap in auditLogBitmap for internal use.
 */
char *auditLog = NULL;
static uint64 auditLogBitmap = 0;

/*
 * String contants for audit types - used when logging to distinguish session
 * vs. object auditing.
 */
#define AUDIT_TYPE_OBJECT	"OBJECT"
#define AUDIT_TYPE_SESSION	"SESSION"

/*
 * String contants for log classes - used when processing tokens in the
 * pgaudit.log GUC.
 */
#define CLASS_DDL			"DDL"
#define CLASS_FUNCTION		"FUNCTION"
#define CLASS_MISC		    "MISC"
#define CLASS_READ			"READ"
#define CLASS_WRITE			"WRITE"

#define CLASS_ALL			"ALL"
#define CLASS_NONE			"NONE"

/* Log class enum used to represent bits in auditLogBitmap */
enum LogClass
{
	LOG_NONE = 0,

	/* SELECT */
	LOG_READ = (1 << 0),

	/* INSERT, UPDATE, DELETE, TRUNCATE */
	LOG_WRITE = (1 << 1),

	/* DDL: CREATE/DROP/ALTER */
	LOG_DDL = (1 << 2),

	/* Function execution */
	LOG_FUNCTION = (1 << 4),

	/* Function execution */
	LOG_MISC = (1 << 5),

	/* Absolutely everything */
	LOG_ALL = ~(uint64)0
};

/* String contants for logging commands */
#define COMMAND_DELETE		"DELETE"
#define COMMAND_EXECUTE		"EXECUTE"
#define COMMAND_INSERT		"INSERT"
#define COMMAND_UPDATE		"UPDATE"
#define COMMAND_SELECT		"SELECT"

#define COMMAND_UNKNOWN		"UNKNOWN"

/* String constants for logging object types */
#define OBJECT_TYPE_COMPOSITE_TYPE	"COMPOSITE TYPE"
#define OBJECT_TYPE_FOREIGN_TABLE	"FOREIGN TABLE"
#define OBJECT_TYPE_FUNCTION		"FUNCTION"
#define OBJECT_TYPE_INDEX			"INDEX"
#define OBJECT_TYPE_TABLE			"TABLE"
#define OBJECT_TYPE_TOASTVALUE		"TOASTVALUE"
#define OBJECT_TYPE_MATVIEW			"MATERIALIZED VIEW"
#define OBJECT_TYPE_SEQUENCE		"SEQUENCE"
#define OBJECT_TYPE_VIEW			"VIEW"

#define OBJECT_TYPE_UNKNOWN			"UNKNOWN"

/*
 * This module collects AuditEvents from various sources (event triggers, and
 * executor/utility hooks) and passes them to the log_audit_event() function.
 *
 * An AuditEvent represents an operation that potentially affects a single
 * object. If an underlying command affects multiple objects multiple
 * AuditEvents must be created to represent it.
 */
typedef struct
{
	LogStmtLevel logStmtLevel;
	NodeTag commandTag;
	const char *command;
	const char *objectType;
	char *objectName;
	const char *commandText;
	bool granted;
} AuditEvent;

/*
 * Set if a function below log_utility_command() has logged the event - prevents
 * more than one function from logging when the event could be logged in
 * multiple places.
 */
bool utilityCommandLogged = false;
AuditEvent utilityAuditEvent;

/*
 * Returns the oid of the role specified in pgaudit.role.
 */
static Oid
audit_role_oid()
{
	HeapTuple roleTup;
	Oid oid = InvalidOid;

	roleTup = SearchSysCache1(AUTHNAME, PointerGetDatum(auditRole));

	if (HeapTupleIsValid(roleTup))
	{
		oid = HeapTupleGetOid(roleTup);
		ReleaseSysCache(roleTup);
	}

	return oid;
}

/*
 * Takes an AuditEvent and returns true or false depending on whether the event
 * should be logged according to the pgaudit.roles/log settings. If it returns
 * true, also fills in the name of the LogClass which it is logged under.
 */
static bool
log_check(AuditEvent *e, const char **classname)
{
	enum LogClass class = LOG_NONE;

	/* By default put everything in the MISC class. */
	*classname = CLASS_MISC;
	class = LOG_MISC;

	/*
	 * Look at the type of the command and decide what LogClass needs to be
	 * enabled for the command to be logged.
	 */
	switch (e->logStmtLevel)
	{
		case LOGSTMT_MOD:
			*classname = CLASS_WRITE;
			class = LOG_WRITE;
			break;

		case LOGSTMT_DDL:
			*classname = CLASS_DDL;
			class = LOG_DDL;

		case LOGSTMT_ALL:
			switch (e->commandTag)
			{
				case T_CopyStmt:
				case T_SelectStmt:
				case T_PrepareStmt:
				case T_PlannedStmt:
				case T_ExecuteStmt:
					*classname = CLASS_READ;
					class = LOG_READ;
					break;

				case T_VacuumStmt:
				case T_ReindexStmt:
					*classname = CLASS_DDL;
					class = LOG_DDL;
					break;

				case T_DoStmt:
					*classname = CLASS_FUNCTION;
					class = LOG_FUNCTION;
					break;

				default:
					break;
			}
			break;

		case LOGSTMT_NONE:
			break;
	}

	/*
	 * We log audit events under the following conditions:
	 *
	 * 1. If the audit role has been explicitly granted permission for
	 *    an operation.
	 */
	if (e->granted)
	{
		return true;
	}

	/* 2. If the event belongs to a class covered by pgaudit.log. */
	if ((auditLogBitmap & class) == class)
	{
		return true;
	}

	return false;
}

/*
 * Takes an AuditEvent and, if it log_check(), writes it to the audit log. The
 * AuditEvent is assumed to be completely filled in by the caller (unknown
 * values must be set to "" so that they can be logged without error checking).
 */
static void
log_audit_event(AuditEvent *e)
{
	const char *classname;

	/* Check that this event should be logged. */
	if (!log_check(e, &classname))
		return;

	/* Log via ereport(). */
	ereport(LOG,
			(errmsg("AUDIT: %s,%s,%s,%s,%s,%s",
					e->granted ? AUDIT_TYPE_OBJECT : AUDIT_TYPE_SESSION,
					classname, e->command, e->objectType, e->objectName,
					e->commandText),
			 errhidestmt(true)));
}

/*
 * Check if the role or any inherited role has any permission in the mask.  The
 * public role is excluded from this check and superuser permissions are not
 * considered.
 */
static bool
log_acl_check(Datum aclDatum, Oid auditOid, AclMode mask)
{
	bool		result = false;
	Acl		   *acl;
	AclItem    *aclItemData;
	int			aclIndex;
	int			aclTotal;

	/* Detoast column's ACL if necessary */
	acl = DatumGetAclP(aclDatum);

	/* Get the acl list and total */
	aclTotal = ACL_NUM(acl);
	aclItemData = ACL_DAT(acl);

	/* Check privileges granted directly to auditOid */
	for (aclIndex = 0; aclIndex < aclTotal; aclIndex++)
	{
		AclItem *aclItem = &aclItemData[aclIndex];

		if (aclItem->ai_grantee == auditOid &&
			aclItem->ai_privs & mask)
		{
			result = true;
			break;
		}
	}

	/*
	 * Check privileges granted indirectly via role memberships. We do this in
	 * a separate pass to minimize expensive indirect membership tests.  In
	 * particular, it's worth testing whether a given ACL entry grants any
	 * privileges still of interest before we perform the has_privs_of_role
	 * test.
	 */
	if (!result)
	{
		for (aclIndex = 0; aclIndex < aclTotal; aclIndex++)
		{
			AclItem *aclItem = &aclItemData[aclIndex];

			/* Don't test public or auditOid (it has been tested already) */
			if (aclItem->ai_grantee == ACL_ID_PUBLIC ||
				aclItem->ai_grantee == auditOid)
				continue;

			/*
			 * Check that the role has the required privileges and that it is
			 * inherited by auditOid.
			 */
			if (aclItem->ai_privs & mask &&
				has_privs_of_role(auditOid, aclItem->ai_grantee))
			{
				result = true;
				break;
			}
		}
	}

	/* if we have a detoasted copy, free it */
	if (acl && (Pointer) acl != DatumGetPointer(aclDatum))
		pfree(acl);

	return result;
}

/*
 * Check if a role has any of the permissions in the mask on a relation.
 */
static bool
log_relation_check(Oid relOid,
				   Oid auditOid,
				   AclMode mask)
{
	bool		result = false;
	HeapTuple	tuple;
	Datum		aclDatum;
	bool		isNull;

	/* Get relation tuple from pg_class */
	tuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relOid));

	/* Return false if tuple is not valid */
	if (!HeapTupleIsValid(tuple))
		return false;

	/* Get the relation's ACL */
	aclDatum = SysCacheGetAttr(RELOID, tuple, Anum_pg_class_relacl,
							   &isNull);

	/* If not null then test */
	if (!isNull)
		result = log_acl_check(aclDatum, auditOid, mask);

	/* Free the relation tuple */
	ReleaseSysCache(tuple);

	return result;
}

/*
 * Check if a role has any of the permissions in the mask on an attribute.
 */
static bool
log_attribute_check(Oid relOid,
					AttrNumber attNum,
					Oid auditOid,
					AclMode mask)
{
	bool		result = false;
	HeapTuple	attTuple;
	Datum		aclDatum;
	bool		isNull;

	/* Get the attribute's ACL */
	attTuple = SearchSysCache2(ATTNUM,
							   ObjectIdGetDatum(relOid),
							   Int16GetDatum(attNum));

	/* Return false if attribute is invalid */
	if (!HeapTupleIsValid(attTuple))
		return false;

	/* Only process attribute that have not been dropped */
	if (!((Form_pg_attribute) GETSTRUCT(attTuple))->attisdropped)
	{
		aclDatum = SysCacheGetAttr(ATTNUM, attTuple, Anum_pg_attribute_attacl,
								   &isNull);

		if (!isNull)
			result = log_acl_check(aclDatum, auditOid, mask);
	}

	/* Free attribute */
	ReleaseSysCache(attTuple);

	return result;
}

/*
 * Check if a role has any of the permissions in the mask on an attribute in
 * the provided set.  If the set is empty, then all valid attributes in the
 * relation will be tested.
 */
static bool
log_attribute_check_any(Oid relOid,
						Oid auditOid,
						Bitmapset *attributeSet,
						AclMode mode)
{
	bool result = false;
	AttrNumber col;
	Bitmapset *tmpSet;

	/* If bms is empty then check for any column match */
	if (bms_is_empty(attributeSet))
	{
		HeapTuple	classTuple;
		AttrNumber	nattrs;
		AttrNumber	curr_att;

		/* Get relation to determine total attribute */
		classTuple = SearchSysCache1(RELOID, ObjectIdGetDatum(relOid));

		if (!HeapTupleIsValid(classTuple))
			return false;

		nattrs = ((Form_pg_class) GETSTRUCT(classTuple))->relnatts;
		ReleaseSysCache(classTuple);

		/* Check each column */
		for (curr_att = 1; curr_att <= nattrs; curr_att++)
		{
			if (log_attribute_check(relOid, curr_att, auditOid, mode))
				return true;
		}
	}

	/* Make a copy of the column set */
	tmpSet = bms_copy(attributeSet);

	/* Check each column */
	while ((col = bms_first_member(tmpSet)) >= 0)
	{
		col += FirstLowInvalidHeapAttributeNumber;

		if (col != InvalidAttrNumber &&
			log_attribute_check(relOid, col, auditOid, mode))
		{
			result = true;
			break;
		}
	}

	/* Free the column set */
	bms_free(tmpSet);

	return result;
}

/*
 * Create AuditEvents for DML operations via executor permissions checks.
 */
static void
log_dml(Oid auditOid, List *rangeTabls)
{
	ListCell *lr;
	bool first = true;

	foreach(lr, rangeTabls)
	{
		Oid relOid;
		Relation rel;
		RangeTblEntry *rte = lfirst(lr);
		AuditEvent auditEvent;

		/* We only care about tables, and can ignore subqueries etc. */
		if (rte->rtekind != RTE_RELATION)
			continue;

		/*
		 * Filter out any system relations
		 */
		relOid = rte->relid;
		rel = relation_open(relOid, NoLock);

		if (IsSystemNamespace(RelationGetNamespace(rel)))
		{
			relation_close(rel, NoLock);
			return;
		}

		/*
		 * We don't have access to the parsetree here, so we have to generate
		 * the node type, object type, and command tag by decoding
		 * rte->requiredPerms and rte->relkind.
		 */
		auditEvent.logStmtLevel = LOGSTMT_MOD;

		if (rte->requiredPerms & ACL_INSERT)
		{
			auditEvent.commandTag = T_InsertStmt;
			auditEvent.command = COMMAND_INSERT;
		}
		else if (rte->requiredPerms & ACL_UPDATE)
		{
			auditEvent.commandTag = T_UpdateStmt;
			auditEvent.command = COMMAND_UPDATE;
		}
		else if (rte->requiredPerms & ACL_DELETE)
		{
			auditEvent.commandTag = T_DeleteStmt;
			auditEvent.command = COMMAND_DELETE;
		}
		else if (rte->requiredPerms & ACL_SELECT)
		{
			auditEvent.logStmtLevel = LOGSTMT_ALL;
			auditEvent.commandTag = T_SelectStmt;
			auditEvent.command = COMMAND_SELECT;
		}
		else
		{
			auditEvent.commandTag = T_Invalid;
			auditEvent.command = COMMAND_UNKNOWN;
		}

		/*
		 * Fill values in the event struct that are required for session
		 * logging.
		 */
		auditEvent.granted = false;
		auditEvent.commandText = debug_query_string;

		/* If this is the first rte then session log */
		if (first)
		{
			auditEvent.objectName = "";
			auditEvent.objectType = "";

			log_audit_event(&auditEvent);

			first = false;
		}

		/* Get the relation type */
		switch (rte->relkind)
		{
			case RELKIND_RELATION:
				auditEvent.objectType = OBJECT_TYPE_TABLE;
				break;

			case RELKIND_INDEX:
				auditEvent.objectType = OBJECT_TYPE_INDEX;
				break;

			case RELKIND_SEQUENCE:
				auditEvent.objectType = OBJECT_TYPE_SEQUENCE;
				break;

			case RELKIND_TOASTVALUE:
				auditEvent.objectType = OBJECT_TYPE_TOASTVALUE;
				break;

			case RELKIND_VIEW:
				auditEvent.objectType = OBJECT_TYPE_VIEW;
				break;

			case RELKIND_COMPOSITE_TYPE:
				auditEvent.objectType = OBJECT_TYPE_COMPOSITE_TYPE;
				break;

			case RELKIND_FOREIGN_TABLE:
				auditEvent.objectType = OBJECT_TYPE_FOREIGN_TABLE;
				break;

			case RELKIND_MATVIEW:
				auditEvent.objectType = OBJECT_TYPE_MATVIEW;
				break;

			default:
				auditEvent.objectType = OBJECT_TYPE_UNKNOWN;
				break;
		}

		/* Get the relation name */
		auditEvent.objectName =
			quote_qualified_identifier(get_namespace_name(
									   RelationGetNamespace(rel)),
									   RelationGetRelationName(rel));
		relation_close(rel, NoLock);


		/* Perform object auditing only if the audit role is valid */
		if (auditOid != InvalidOid)
		{
			AclMode auditPerms = (ACL_SELECT | ACL_UPDATE | ACL_INSERT) &
								 rte->requiredPerms;

			/*
			 * If any of the required permissions for the relation are granted
			 * to the audit role then audit the relation
			 */
			if (log_relation_check(relOid, auditOid, auditPerms))
			{
				auditEvent.granted = true;
			}

			/*
			 * Else check if the audit role has column-level permissions for
			 * select, insert, or update.
			 */
			else if (auditPerms != 0)
			{
				/*
				 * Check the select columns to see if the audit role has
				 * priveleges on any of them.
				 */
				if (auditPerms & ACL_SELECT)
				{
					auditEvent.granted =
						log_attribute_check_any(relOid, auditOid,
												rte->selectedCols,
												ACL_SELECT);
				}

				/*
				 * Check the modified columns to see if the audit role has
				 * privileges on any of them.
				 */
				if (!auditEvent.granted)
				{
					auditPerms &= (ACL_INSERT | ACL_UPDATE);

					if (auditPerms)
					{
						auditEvent.granted =
							log_attribute_check_any(relOid, auditOid,
													rte->modifiedCols,
													auditPerms);
					}
				}
			}
		}

		/* Only do relation level logging if a grant was found. */
		if (auditEvent.granted)
		{
			log_audit_event(&auditEvent);
		}

		pfree(auditEvent.objectName);
	}
}

/*
 * Create AuditEvents for certain kinds of CREATE, ALTER, and DELETE statements
 * where the object can be logged.
 */
static void
log_create_alter_drop(Oid classId,
					  Oid objectId)
{
	/* Only perform when class is relation */
	if (classId == RelationRelationId)
	{
		Relation rel;
		Form_pg_class class;

		/* Open the relation */
		rel = relation_open(objectId, NoLock);

		/* Filter out any system relations */
		if (IsToastNamespace(RelationGetNamespace(rel)))
		{
			relation_close(rel, NoLock);
			return;
		}

		/* Get rel information and close it */
		class = RelationGetForm(rel);
		utilityAuditEvent.objectName =
			quote_qualified_identifier(get_namespace_name(
									   RelationGetNamespace(rel)),
									   RelationGetRelationName(rel));
		relation_close(rel, NoLock);

		/* Set object type based on relkind */
		switch (class->relkind)
		{
			case RELKIND_RELATION:
				utilityAuditEvent.objectType = OBJECT_TYPE_TABLE;
				break;

			case RELKIND_INDEX:
				utilityAuditEvent.objectType = OBJECT_TYPE_INDEX;
				break;

			case RELKIND_SEQUENCE:
				utilityAuditEvent.objectType = OBJECT_TYPE_SEQUENCE;
				break;

			case RELKIND_VIEW:
				utilityAuditEvent.objectType = OBJECT_TYPE_VIEW;
				break;

			case RELKIND_COMPOSITE_TYPE:
				utilityAuditEvent.objectType = OBJECT_TYPE_COMPOSITE_TYPE;
				break;

			case RELKIND_FOREIGN_TABLE:
				utilityAuditEvent.objectType = OBJECT_TYPE_FOREIGN_TABLE;
				break;

			case RELKIND_MATVIEW:
				utilityAuditEvent.objectType = OBJECT_TYPE_MATVIEW;
				break;

			/*
			 * Any other cases will be handled by log_utility_command().
			 */
			default:
				return;
				break;
		}

		/* Log the event */
		log_audit_event(&utilityAuditEvent);
		utilityCommandLogged = true;
	}
}

/*
 * Create AuditEvents for non-catalog function execution, as detected by
 * log_object_access() below.
 */
static void
log_function_execute(Oid objectId)
{
	HeapTuple proctup;
	Form_pg_proc proc;

	/* Get info about the function. */
	proctup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));

	if (!proctup)
		elog(ERROR, "cache lookup failed for function %u", objectId);
	proc = (Form_pg_proc) GETSTRUCT(proctup);

	/*
	 * Logging execution of all pg_catalog functions would make the log
	 * unusably noisy.
	 */
	if (IsSystemNamespace(proc->pronamespace))
	{
		ReleaseSysCache(proctup);
		return;
	}

	/* Generate the fully-qualified function name. */
	utilityAuditEvent.objectName =
		quote_qualified_identifier(get_namespace_name(proc->pronamespace),
								   NameStr(proc->proname));
	ReleaseSysCache(proctup);

	/* Log the event */
	utilityAuditEvent.logStmtLevel = LOGSTMT_ALL;
	utilityAuditEvent.commandTag = T_DoStmt;
	utilityAuditEvent.command = COMMAND_EXECUTE;
	utilityAuditEvent.objectType = OBJECT_TYPE_FUNCTION;
	utilityAuditEvent.commandText = debug_query_string;

	log_audit_event(&utilityAuditEvent);
	utilityCommandLogged = true;
}

/*
 * Log object accesses (which is more about DDL than DML, even though it
 * sounds like the latter).
 */
static void
log_object_access(ObjectAccessType access,
				  Oid classId,
				  Oid objectId,
				  int subId,
				  void *arg)
{
	switch (access)
	{
		/* Log execute. */
		case OAT_FUNCTION_EXECUTE:
			log_function_execute(objectId);
			break;

		/* Log create. */
		case OAT_POST_CREATE:
			{
				ObjectAccessPostCreate *pc = arg;

				if (pc->is_internal)
					return;

				log_create_alter_drop(classId, objectId);
			}
			break;

		/* Log alter. */
		case OAT_POST_ALTER:
			{
				ObjectAccessPostAlter *pa = arg;

				if (pa->is_internal)
					return;

				log_create_alter_drop(classId, objectId);
			}
			break;

		/* Log drop. */
		case OAT_DROP:
		{
			ObjectAccessDrop *drop = arg;

			if (drop->dropflags & PERFORM_DELETION_INTERNAL)
				return;

			log_create_alter_drop(classId, objectId);
		}
		break;

		/* All others processed by log_utility_command() */
		default:
			break;
	}
}

/*
 * Hook functions
 */
static ExecutorCheckPerms_hook_type next_ExecutorCheckPerms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static object_access_hook_type next_object_access_hook = NULL;

/*
 * Hook ExecutorCheckPerms to do session and object auditing for DML.
 */
static bool
pgaudit_ExecutorCheckPerms_hook(List *rangeTabls, bool abort)
{
	Oid auditOid = audit_role_oid();

	if ((auditOid != InvalidOid || auditLogBitmap != 0) &&
		!IsAbortedTransactionBlockState())
		log_dml(auditOid, rangeTabls);

	if (next_ExecutorCheckPerms_hook &&
		!(*next_ExecutorCheckPerms_hook) (rangeTabls, abort))
		return false;

	return true;
}

/*
 * Hook ProcessUtility to do session auditing for DDL and utility commands.
 */
static void
pgaudit_ProcessUtility_hook(Node *parsetree,
							const char *queryString,
							ProcessUtilityContext context,
							ParamListInfo params,
							DestReceiver *dest,
							char *completionTag)
{
	/* Create the utility audit event. */
	utilityCommandLogged = false;

	utilityAuditEvent.logStmtLevel = GetCommandLogLevel(parsetree);
	utilityAuditEvent.commandTag = nodeTag(parsetree);
	utilityAuditEvent.command = CreateCommandTag(parsetree);
	utilityAuditEvent.objectName = "";
	utilityAuditEvent.objectType = "";
	utilityAuditEvent.commandText = debug_query_string;
	utilityAuditEvent.granted = false;

	/* Call the standard process utility chain. */
	if (next_ProcessUtility_hook)
		(*next_ProcessUtility_hook) (parsetree, queryString, context,
									 params, dest, completionTag);
	else
		standard_ProcessUtility(parsetree, queryString, context,
								params, dest, completionTag);

	/* Log the utility command if logging is on, the command has not already
	 * been logged by another hook, and the transaction is not aborted */
	if (auditLogBitmap != 0 && !utilityCommandLogged &&
		!IsAbortedTransactionBlockState())
	{
		log_audit_event(&utilityAuditEvent);
	}
}

/*
 * Hook object_access_hook to provide fully-qualified object names for execute,
 * create, drop, and alter commands.  Most of the audit information is filled in
 * by log_utility_command().
 */
static void
pgaudit_object_access_hook(ObjectAccessType access,
						   Oid classId,
						   Oid objectId,
						   int subId,
						   void *arg)
{
	if (auditLogBitmap != 0 && !IsAbortedTransactionBlockState())
		log_object_access(access, classId, objectId, subId, arg);

	if (next_object_access_hook)
		(*next_object_access_hook) (access, classId, objectId, subId, arg);
}

/*
 * GUC check and assign functions
 */

/*
 * Take a pgaudit.log value such as "read, write, dml", verify that each of the
 * comma-separated tokens corresponds to a LogClass value, and convert them into
 * a bitmap that log_audit_event can check.
 */
static bool
check_pgaudit_log(char **newval, void **extra, GucSource source)
{
	List *flags;
	char *rawval;
	ListCell *lt;
	uint64 *f;

	/* Make sure newval is a comma-separated list of tokens. */
	rawval = pstrdup(*newval);
	if (!SplitIdentifierString(rawval, ',', &flags))
	{
		GUC_check_errdetail("List syntax is invalid");
		list_free(flags);
		pfree(rawval);
		return false;
	}

	/*
	 * Check that we recognise each token, and add it to the bitmap we're building
	 * up in a newly-allocated uint64 *f.
	 */
	f = (uint64 *) malloc(sizeof(uint64));
	if (!f)
		return false;
	*f = 0;

	foreach(lt, flags)
	{
		bool subtract = false;
		uint64 class;

		/* Retrieve a token */
		char *token = (char *)lfirst(lt);

		/* If token is preceded by -, then then token is subtractive. */
		if (strstr(token, "-") == token)
		{
			token = token + 1;
			subtract = true;
		}

		/* Test each token. */
		if (pg_strcasecmp(token, CLASS_NONE) == 0)
			class = LOG_NONE;
		else if (pg_strcasecmp(token, CLASS_ALL) == 0)
			class = LOG_ALL;
		else if (pg_strcasecmp(token, CLASS_DDL) == 0)
			class = LOG_DDL;
		else if (pg_strcasecmp(token, CLASS_FUNCTION) == 0)
			class = LOG_FUNCTION;
		else if (pg_strcasecmp(token, CLASS_MISC) == 0)
			class = LOG_MISC;
		else if (pg_strcasecmp(token, CLASS_READ) == 0)
			class = LOG_READ;
		else if (pg_strcasecmp(token, CLASS_WRITE) == 0)
			class = LOG_WRITE;
		else
		{
			free(f);
			pfree(rawval);
			list_free(flags);
			return false;
		}

		/* Add or subtract class bits from the log bitmap. */
		if (subtract)
			*f &= ~class;
		else
			*f |= class;
	}

	pfree(rawval);
	list_free(flags);

	/*
	 * Store the bitmap for assign_pgaudit_log.
	 */
	*extra = f;

	return true;
}

/*
 * Set pgaudit_log from extra (ignoring newval, which has already been converted
 * to a bitmap above). Note that extra may not be set if the assignment is to be
 * suppressed.
 */
static void
assign_pgaudit_log(const char *newval, void *extra)
{
	if (extra)
		auditLogBitmap = *(uint64 *)extra;
}

/*
 * Define GUC variables and install hooks upon module load.
 */
void
_PG_init(void)
{
	if (IsUnderPostmaster)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pgaudit must be loaded via shared_preload_libraries")));

	/*
	 * pgaudit.role = "role1"
	 *
	 * This variable defines a role to be used for auditing.
	 */
	DefineCustomStringVariable("pgaudit.role",
							   "Enable auditing for role",
							   NULL,
							   &auditRole,
							   "",
							   PGC_SUSET,
							   GUC_LIST_INPUT | GUC_NOT_IN_SAMPLE,
							   NULL, NULL, NULL);

	/*
	 * pgaudit.log = "read, write, ddl"
	 *
	 * This variables controls what classes of commands are logged.
	 */
	DefineCustomStringVariable("pgaudit.log",
							   "Enable auditing for classes of commands",
							   NULL,
							   &auditLog,
							   "none",
							   PGC_SUSET,
							   GUC_LIST_INPUT | GUC_NOT_IN_SAMPLE,
							   check_pgaudit_log,
							   assign_pgaudit_log,
							   NULL);

	/*
	 * Install our hook functions after saving the existing pointers to preserve
	 * the chain.
	 */
	next_ExecutorCheckPerms_hook = ExecutorCheckPerms_hook;
	ExecutorCheckPerms_hook = pgaudit_ExecutorCheckPerms_hook;

	next_ProcessUtility_hook = ProcessUtility_hook;
	ProcessUtility_hook = pgaudit_ProcessUtility_hook;

	next_object_access_hook = object_access_hook;
	object_access_hook = pgaudit_object_access_hook;
}
