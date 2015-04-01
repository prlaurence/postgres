/*------------------------------------------------------------------------------
 * pg_audit.c
 *
 * An auditing extension for PostgreSQL. Improves on standard statement logging
 * by adding more logging classes, object level logging, and providing
 * fully-qualified object names for all DML and many DDL statements (See
 * pg_audit.sgml for details).
 *
 * Copyright (c) 2014-2015, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		  contrib/pg_audit/pg_audit.c
 *------------------------------------------------------------------------------
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
 * Event trigger prototypes
 */
Datum pg_audit_ddl_command_end(PG_FUNCTION_ARGS);
Datum pg_audit_sql_drop(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(pg_audit_ddl_command_end);
PG_FUNCTION_INFO_V1(pg_audit_sql_drop);

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
 * String constants for audit types - used when logging to distinguish session
 * vs. object auditing.
 */
#define AUDIT_TYPE_OBJECT	"OBJECT"
#define AUDIT_TYPE_SESSION	"SESSION"

/*
 * String constants for log classes - used when processing tokens in the
 * pgaudit.log GUC.
 */
#define CLASS_DDL			"DDL"
#define CLASS_FUNCTION		"FUNCTION"
#define CLASS_MISC			"MISC"
#define CLASS_PARAMETER		"PARAMETER"
#define CLASS_READ			"READ"
#define CLASS_WRITE			"WRITE"

#define CLASS_ALL			"ALL"
#define CLASS_NONE			"NONE"

/* Log class enum used to represent bits in auditLogBitmap */
enum LogClass
{
	LOG_NONE = 0,

	/* DDL: CREATE/DROP/ALTER */
	LOG_DDL = (1 << 1),

	/* Function execution */
	LOG_FUNCTION = (1 << 2),

	/* Statements not covered by another class */
	LOG_MISC = (1 << 3),

	/* Function execution */
	LOG_PARAMETER = (1 << 4),

	/* SELECT */
	LOG_READ = (1 << 5),

	/* INSERT, UPDATE, DELETE, TRUNCATE */
	LOG_WRITE = (1 << 6),

	/* Absolutely everything */
	LOG_ALL = ~(uint64)0
};

/* String constants for logging commands */
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
 * An AuditEvent represents an operation that potentially affects a single
 * object. If a statement affects multiple objects multiple AuditEvents must be
 * created to represent it.
 */
typedef struct
{
	int64 statementId;
	int64 substatementId;

	LogStmtLevel logStmtLevel;
	NodeTag commandTag;
	const char *command;
	const char *objectType;
	char *objectName;
	const char *commandText;
	ParamListInfo paramList;

	bool granted;
	bool logged;
} AuditEvent;

/*
 * A simple FIFO queue to keep track of the current stack of audit events.
 */
typedef struct AuditEventStackItem
{
	struct AuditEventStackItem *next;

	AuditEvent auditEvent;

	int64 stackId;

	MemoryContext contextAudit;
	MemoryContextCallback contextCallback;
} AuditEventStackItem;

AuditEventStackItem *auditEventStack = NULL;

/*
 * Track when an internal statement is running so it is not logged
 */
static bool internalStatement = false;

/*
 * Track running total for statements and substatements and whether or not
 * anything has been logged since this statement began.
 */
static int64 statementTotal = 0;
static int64 substatementTotal = 0;
static int64 stackTotal = 0;

static bool statementLogged = false;

/*
 * Stack functions
 *
 * Audit events can go down to multiple levels so a stack is maintained to keep
 * track of them.
 */

/*
 * Respond to callbacks registered with MemoryContextRegisterResetCallback().
 * Removes the event(s) off the stack that have become obsolete once the
 * MemoryContext has been freed.  The callback should always be freeing the top
 * of the stack, but the code is tolerant of out-of-order callbacks.
 */
static void
stack_free(void *stackFree)
{
	AuditEventStackItem *nextItem = auditEventStack;

	/* Only process if the stack contains items */
	while (nextItem != NULL)
	{
		/* Check if this item matches the item to be freed */
		if (nextItem == (AuditEventStackItem *)stackFree)
		{
			/* Move top of stack to the item after the freed item */
			auditEventStack = nextItem->next;

			/* If the stack is not empty */
			if (auditEventStack == NULL)
			{
				/* Reset internal statement in case of error */
				internalStatement = false;

				/* Reset sub statement total */
				substatementTotal = 0;

				/* Reset statement logged flag total */
				statementLogged = false;
			}

			return;
		}

		/* Still looking, test the next item */
		nextItem = nextItem->next;
	}
}

/*
 * Push a new audit event onto the stack and create a new memory context to
 * store it.
 */
static AuditEventStackItem *
stack_push()
{
	MemoryContext contextAudit;
	MemoryContext contextOld;
	AuditEventStackItem *stackItem;

	/* Create a new memory context */
	contextAudit = AllocSetContextCreate(CurrentMemoryContext,
										 "pg_audit stack context",
										 ALLOCSET_DEFAULT_MINSIZE,
										 ALLOCSET_DEFAULT_INITSIZE,
										 ALLOCSET_DEFAULT_MAXSIZE);
	contextOld = MemoryContextSwitchTo(contextAudit);

	/* Allocate the stack item */
	stackItem = palloc0(sizeof(AuditEventStackItem));

	/* Store memory contexts */
	stackItem->contextAudit = contextAudit;

	/* If item already on stack then push it down */
	if (auditEventStack != NULL)
		stackItem->next = auditEventStack;
	else
		stackItem->next = NULL;

	/*
	 * Create the unique stackId - used to keep the stack sane when memory
	 * contexts are freed unexpectedly.
	 */
	stackItem->stackId = ++stackTotal;

	/*
	 * Setup a callback in case an error happens.  stack_free() will truncate
	 * the stack at this item.
	 */
	stackItem->contextCallback.func = stack_free;
	stackItem->contextCallback.arg = (void *)stackItem;
	MemoryContextRegisterResetCallback(contextAudit,
									   &stackItem->contextCallback);

	/* Push item on the stack */
	auditEventStack = stackItem;

	/* Return to the old memory context */
	MemoryContextSwitchTo(contextOld);

	/* Return the stack item */
	return stackItem;
}

/*
 * Pop an audit event from the stack by deleting the memory context that
 * contains it.  The callback to stack_free() does the actual pop.
 */
static void
stack_pop(int64 stackId)
{
	/* Make sure what we want to delete is at the top of the stack */
	if (auditEventStack != NULL && auditEventStack->stackId == stackId)
	{
		MemoryContextDelete(auditEventStack->contextAudit);
	}
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
 * Appends a properly quoted CSV field to StringInfo.
 */
static void
append_valid_csv(StringInfoData *buffer, const char *appendStr)
{
	const char *pChar;

	/*
	 * If the append string is null then return.  NULL fields are not quoted
	 * in CSV
	 */
	if (appendStr == NULL)
		return;

	/* Only format for CSV if appendStr contains: ", comma, \n, \r */
	if (strstr(appendStr, ",") || strstr(appendStr, "\"") ||
		strstr(appendStr, "\n") || strstr(appendStr, "\r"))
	{
		appendStringInfoCharMacro(buffer, '"');

		for (pChar = appendStr; *pChar; pChar++)
		{
			if (*pChar == '"') /* double single quotes */
				appendStringInfoCharMacro(buffer, *pChar);

			appendStringInfoCharMacro(buffer, *pChar);
		}

		appendStringInfoCharMacro(buffer, '"');
	}
	/* Else just append */
	else
	{
		appendStringInfoString(buffer, appendStr);
	}
}

/*
 * Takes an AuditEvent and, if it log_check(), writes it to the audit log. The
 * AuditEvent is assumed to be completely filled in by the caller (unknown
 * values must be set to "" so that they can be logged without error checking).
 */
static void
log_audit_event(AuditEventStackItem *stackItem)
{
	const char *classname;
	MemoryContext contextOld;
	StringInfoData auditStr;

	/* Check that this event should be logged. */
	if (!log_check(&stackItem->auditEvent, &classname))
		return;

	/* Use audit memory context in case something is not freed */
	contextOld = MemoryContextSwitchTo(stackItem->contextAudit);

	/* Set statement and substatement Ids */
	if (stackItem->auditEvent.statementId == 0)
	{
		/* If nothing has been logged yet then create a new statement Id */
		if (!statementLogged)
		{
			statementTotal++;
			statementLogged = true;
		}

		stackItem->auditEvent.statementId = statementTotal;
		stackItem->auditEvent.substatementId = ++substatementTotal;
	}

	/* Create the audit string */
	initStringInfo(&auditStr);

	append_valid_csv(&auditStr, stackItem->auditEvent.command);
	appendStringInfoCharMacro(&auditStr, ',');

	append_valid_csv(&auditStr, stackItem->auditEvent.objectType);
	appendStringInfoCharMacro(&auditStr, ',');

	append_valid_csv(&auditStr, stackItem->auditEvent.objectName);
	appendStringInfoCharMacro(&auditStr, ',');

	append_valid_csv(&auditStr, stackItem->auditEvent.commandText);

	/* If parameter logging is turned on and there are parameters to log */
	if (auditLogBitmap & LOG_PARAMETER &&
		stackItem->auditEvent.paramList != NULL &&
		stackItem->auditEvent.paramList->numParams > 0 &&
		!IsAbortedTransactionBlockState())
	{
		ParamListInfo paramList = stackItem->auditEvent.paramList;
		int paramIdx;

		/* Iterate through all params */
		for (paramIdx = 0; paramIdx < paramList->numParams; paramIdx++)
		{
			ParamExternData *prm = &paramList->params[paramIdx];
			Oid 			 typeOutput;
			bool 			 typeIsVarLena;
			char 			*paramStr;

			/* Add a comma for each param */
			appendStringInfoCharMacro(&auditStr, ',');

			/* Skip this param if null or if oid is invalid */
			if (prm->isnull || !OidIsValid(prm->ptype))
			{
				continue;
			}

			/* Output the string */
			getTypeOutputInfo(prm->ptype, &typeOutput, &typeIsVarLena);
			paramStr = OidOutputFunctionCall(typeOutput, prm->value);

			append_valid_csv(&auditStr, paramStr);
			pfree(paramStr);
		}
	}

	/* Log the audit string */
	ereport(LOG,
		(errmsg("AUDIT: %s,%ld,%ld,%s,%s",
			stackItem->auditEvent.granted ?
				AUDIT_TYPE_OBJECT : AUDIT_TYPE_SESSION,
			stackItem->auditEvent.statementId,
			stackItem->auditEvent.substatementId,
			classname, auditStr.data),
		 errhidestmt(true)));

	/* Mark the audit event as logged */
	stackItem->auditEvent.logged = true;

	/* Switch back to the old memory context */
	MemoryContextSwitchTo(contextOld);
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
	AclItem	   *aclItemData;
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

	/* bms_first_member is destructive, so make a copy before using it. */
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
 * Create AuditEvents for SELECT/DML operations via executor permissions checks.
 */
static void
log_select_dml(Oid auditOid, List *rangeTabls)
{
	ListCell *lr;
	bool first = true;
	bool found = false;

	/* Do not log if this is an internal statement */
	if (internalStatement)
		return;

	foreach(lr, rangeTabls)
	{
		Oid relOid;
		Relation rel;
		RangeTblEntry *rte = lfirst(lr);

		/* We only care about tables, and can ignore subqueries etc. */
		if (rte->rtekind != RTE_RELATION)
			continue;

		found = true;

		/*
		 * Filter out any system relations
		 */
		relOid = rte->relid;
		rel = relation_open(relOid, NoLock);

		if (IsSystemNamespace(RelationGetNamespace(rel)))
		{
			relation_close(rel, NoLock);
			continue;
		}

		/*
		 * We don't have access to the parsetree here, so we have to generate
		 * the node type, object type, and command tag by decoding
		 * rte->requiredPerms and rte->relkind.
		 */
		if (rte->requiredPerms & ACL_INSERT)
		{
			auditEventStack->auditEvent.logStmtLevel = LOGSTMT_MOD;
			auditEventStack->auditEvent.commandTag = T_InsertStmt;
			auditEventStack->auditEvent.command = COMMAND_INSERT;
		}
		else if (rte->requiredPerms & ACL_UPDATE)
		{
			auditEventStack->auditEvent.logStmtLevel = LOGSTMT_MOD;
			auditEventStack->auditEvent.commandTag = T_UpdateStmt;
			auditEventStack->auditEvent.command = COMMAND_UPDATE;
		}
		else if (rte->requiredPerms & ACL_DELETE)
		{
			auditEventStack->auditEvent.logStmtLevel = LOGSTMT_MOD;
			auditEventStack->auditEvent.commandTag = T_DeleteStmt;
			auditEventStack->auditEvent.command = COMMAND_DELETE;
		}
		else if (rte->requiredPerms & ACL_SELECT)
		{
			auditEventStack->auditEvent.logStmtLevel = LOGSTMT_ALL;
			auditEventStack->auditEvent.commandTag = T_SelectStmt;
			auditEventStack->auditEvent.command = COMMAND_SELECT;
		}
		else
		{
			auditEventStack->auditEvent.logStmtLevel = LOGSTMT_ALL;
			auditEventStack->auditEvent.commandTag = T_Invalid;
			auditEventStack->auditEvent.command = COMMAND_UNKNOWN;
		}

		/*
		 * Fill values in the event struct that are required for session
		 * logging.
		 */
		auditEventStack->auditEvent.granted = false;

		/* If this is the first rte then session log */
		if (first)
		{
			auditEventStack->auditEvent.objectName = "";
			auditEventStack->auditEvent.objectType = "";

			log_audit_event(auditEventStack);

			first = false;
		}

		/* Get the relation type */
		switch (rte->relkind)
		{
			case RELKIND_RELATION:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_TABLE;
				break;

			case RELKIND_INDEX:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_INDEX;
				break;

			case RELKIND_SEQUENCE:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_SEQUENCE;
				break;

			case RELKIND_TOASTVALUE:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_TOASTVALUE;
				break;

			case RELKIND_VIEW:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_VIEW;
				break;

			case RELKIND_COMPOSITE_TYPE:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_COMPOSITE_TYPE;
				break;

			case RELKIND_FOREIGN_TABLE:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_FOREIGN_TABLE;
				break;

			case RELKIND_MATVIEW:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_MATVIEW;
				break;

			default:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_UNKNOWN;
				break;
		}

		/* Get the relation name */
		auditEventStack->auditEvent.objectName =
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
				auditEventStack->auditEvent.granted = true;
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
					auditEventStack->auditEvent.granted =
						log_attribute_check_any(relOid, auditOid,
												rte->selectedCols,
												ACL_SELECT);
				}

				/*
				 * Check the modified columns to see if the audit role has
				 * privileges on any of them.
				 */
				if (!auditEventStack->auditEvent.granted)
				{
					auditPerms &= (ACL_INSERT | ACL_UPDATE);

					if (auditPerms)
					{
						auditEventStack->auditEvent.granted =
							log_attribute_check_any(relOid, auditOid,
													rte->modifiedCols,
													auditPerms);
					}
				}
			}
		}

		/* Only do relation level logging if a grant was found. */
		if (auditEventStack->auditEvent.granted)
		{
			auditEventStack->auditEvent.logged = false;
			log_audit_event(auditEventStack);
		}

		pfree(auditEventStack->auditEvent.objectName);
	}

	/*
	 * If no tables were found that means that RangeTbls was empty or all
	 * relations were in the system schema.  In that case still log a
	 * session record.
	 */
	if (!found)
	{
		auditEventStack->auditEvent.granted = false;
		auditEventStack->auditEvent.logged = false;

		log_audit_event(auditEventStack);
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
		auditEventStack->auditEvent.objectName =
			quote_qualified_identifier(get_namespace_name(
									   RelationGetNamespace(rel)),
									   RelationGetRelationName(rel));
		relation_close(rel, NoLock);

		/* Set object type based on relkind */
		switch (class->relkind)
		{
			case RELKIND_RELATION:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_TABLE;
				break;

			case RELKIND_INDEX:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_INDEX;
				break;

			case RELKIND_SEQUENCE:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_SEQUENCE;
				break;

			case RELKIND_VIEW:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_VIEW;
				break;

			case RELKIND_COMPOSITE_TYPE:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_COMPOSITE_TYPE;
				break;

			case RELKIND_FOREIGN_TABLE:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_FOREIGN_TABLE;
				break;

			case RELKIND_MATVIEW:
				auditEventStack->auditEvent.objectType =
					OBJECT_TYPE_MATVIEW;
				break;

			/*
			 * Any other cases will be handled by log_utility_command().
			 */
			default:
				return;
				break;
		}
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
	AuditEventStackItem *stackItem;

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

	/* Push audit event onto the stack */
	stackItem = stack_push();

	/* Generate the fully-qualified function name. */
	stackItem->auditEvent.objectName =
		quote_qualified_identifier(get_namespace_name(proc->pronamespace),
								   NameStr(proc->proname));
	ReleaseSysCache(proctup);

	/* Log the function call */
	stackItem->auditEvent.logStmtLevel = LOGSTMT_ALL;
	stackItem->auditEvent.commandTag = T_DoStmt;
	stackItem->auditEvent.command = COMMAND_EXECUTE;
	stackItem->auditEvent.objectType = OBJECT_TYPE_FUNCTION;
	stackItem->auditEvent.commandText = stackItem->next->auditEvent.commandText;

	log_audit_event(stackItem);

	/* Pop audit event from the stack */
	stack_pop(stackItem->stackId);
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
		/* Log execute */
		case OAT_FUNCTION_EXECUTE:
			if (auditLogBitmap & LOG_FUNCTION)
				log_function_execute(objectId);
			break;

		/* Log create */
		case OAT_POST_CREATE:
			if (auditLogBitmap & LOG_DDL)
			{
				ObjectAccessPostCreate *pc = arg;

				if (pc->is_internal)
					return;

				log_create_alter_drop(classId, objectId);
			}
			break;

		/* Log alter */
		case OAT_POST_ALTER:
			if (auditLogBitmap & LOG_DDL)
			{
				ObjectAccessPostAlter *pa = arg;

				if (pa->is_internal)
					return;

				log_create_alter_drop(classId, objectId);
			}
			break;

		/* Log drop */
		case OAT_DROP:
			if (auditLogBitmap & LOG_DDL)
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
static ExecutorStart_hook_type next_ExecutorStart_hook = NULL;
static ExecutorEnd_hook_type next_ExecutorEnd_hook = NULL;

/*
 * Hook ExecutorStart to get the query text and basic command type for queries
 * that do not contain a table so can't be idenitified accurately in
 * ExecutorCheckPerms.
 */
static void
pgaudit_ExecutorStart_hook(QueryDesc *queryDesc, int eflags)
{
	AuditEventStackItem *stackItem = NULL;

	if (!internalStatement)
	{
		/* Allocate the audit event */
		stackItem = stack_push();

		/* Initialize command */
		switch (queryDesc->operation)
		{
			case CMD_SELECT:
				stackItem->auditEvent.logStmtLevel = LOGSTMT_ALL;
				stackItem->auditEvent.commandTag = T_SelectStmt;
				stackItem->auditEvent.command = COMMAND_SELECT;
				break;

			case CMD_INSERT:
				stackItem->auditEvent.logStmtLevel = LOGSTMT_MOD;
				stackItem->auditEvent.commandTag = T_InsertStmt;
				stackItem->auditEvent.command = COMMAND_INSERT;
				break;

			case CMD_UPDATE:
				stackItem->auditEvent.logStmtLevel = LOGSTMT_MOD;
				stackItem->auditEvent.commandTag = T_UpdateStmt;
				stackItem->auditEvent.command = COMMAND_UPDATE;
				break;

			case CMD_DELETE:
				stackItem->auditEvent.logStmtLevel = LOGSTMT_MOD;
				stackItem->auditEvent.commandTag = T_DeleteStmt;
				stackItem->auditEvent.command = COMMAND_DELETE;
				break;

			default:
				stackItem->auditEvent.logStmtLevel = LOGSTMT_ALL;
				stackItem->auditEvent.commandTag = T_Invalid;
				stackItem->auditEvent.command = COMMAND_UNKNOWN;
				break;
		}

		/* Initialize the audit event */
		stackItem->auditEvent.objectName = "";
		stackItem->auditEvent.objectType = "";
		stackItem->auditEvent.commandText = queryDesc->sourceText;
		stackItem->auditEvent.paramList = queryDesc->params;
	}

	/* Call the previous hook or standard function */
	if (next_ExecutorStart_hook)
		next_ExecutorStart_hook(queryDesc, eflags);
	else
		standard_ExecutorStart(queryDesc, eflags);
}

/*
 * Hook ExecutorCheckPerms to do session and object auditing for DML.
 */
static bool
pgaudit_ExecutorCheckPerms_hook(List *rangeTabls, bool abort)
{
	Oid auditOid;

	/* Get the audit oid if the role exists. */
	auditOid = get_role_oid(auditRole, true);

	/* Log DML if the audit role is valid or session logging is enabled. */
	if ((auditOid != InvalidOid || auditLogBitmap != 0) &&
		!IsAbortedTransactionBlockState())
		log_select_dml(auditOid, rangeTabls);

	/* Call the next hook function. */
	if (next_ExecutorCheckPerms_hook &&
		!(*next_ExecutorCheckPerms_hook) (rangeTabls, abort))
		return false;

	return true;
}

/*
 * Hook ExecutorEnd to pop statement audit event off the stack.
 */
static void
pgaudit_ExecutorEnd_hook(QueryDesc *queryDesc)
{
	/* Call the next hook or standard function */
	if (next_ExecutorEnd_hook)
		next_ExecutorEnd_hook(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);

	/* Pop the audit event off the stack */
	if (!internalStatement)
	{
		stack_pop(auditEventStack->stackId);
	}
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
	AuditEventStackItem *stackItem = NULL;
	int64 stackId;

	/* Allocate the audit event */
	if (!IsAbortedTransactionBlockState())
	{
		/* Process top level utility statement */
		if (context == PROCESS_UTILITY_TOPLEVEL)
		{
			if (auditEventStack != NULL)
				elog(ERROR, "pg_audit stack is not empty");

			/* Set params */
			stackItem = stack_push();
			stackItem->auditEvent.paramList = params;
		}
		else
			stackItem = stack_push();

		stackId = stackItem->stackId;
		stackItem->auditEvent.logStmtLevel = GetCommandLogLevel(parsetree);
		stackItem->auditEvent.commandTag = nodeTag(parsetree);
		stackItem->auditEvent.command = CreateCommandTag(parsetree);
		stackItem->auditEvent.objectName = "";
		stackItem->auditEvent.objectType = "";
		stackItem->auditEvent.commandText = queryString;

		/*
		 * If this is a DO block log it before calling the next ProcessUtility
		 * hook.
		 */
		if (auditLogBitmap != 0 &&
			stackItem->auditEvent.commandTag == T_DoStmt &&
			!IsAbortedTransactionBlockState())
		{
			log_audit_event(stackItem);
		}
	}

	/* Call the standard process utility chain. */
	if (next_ProcessUtility_hook)
		(*next_ProcessUtility_hook) (parsetree, queryString, context,
									 params, dest, completionTag);
	else
		standard_ProcessUtility(parsetree, queryString, context,
								params, dest, completionTag);

	/* Process the audit event if there is one. */
	if (stackItem != NULL)
	{
		/* Log the utility command if logging is on, the command has not already
		 * been logged by another hook, and the transaction is not aborted. */
		if (auditLogBitmap != 0 && !stackItem->auditEvent.logged &&
			!IsAbortedTransactionBlockState())
			log_audit_event(stackItem);

		stack_pop(stackId);
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
	if (auditLogBitmap != 0 && !IsAbortedTransactionBlockState() &&
		auditLogBitmap & (LOG_DDL | LOG_FUNCTION))
		log_object_access(access, classId, objectId, subId, arg);

	if (next_object_access_hook)
		(*next_object_access_hook) (access, classId, objectId, subId, arg);
}

/*
 * Event trigger functions
 */

/*
 * Supply additional data for (non drop) statements that have event trigger
 * support and can be deparsed.
 */
Datum
pg_audit_ddl_command_end(PG_FUNCTION_ARGS)
{
	/* Continue only if session logging is enabled */
	if (auditLogBitmap != LOG_DDL)
	{
		EventTriggerData *eventData;
		int				  result, row;
		TupleDesc		  spiTupDesc;
		const char		 *query;
		MemoryContext 	  contextQuery;
		MemoryContext 	  contextOld;

		/* This is an internal statement - do not log it */
		internalStatement = true;

		/* Make sure the fuction was fired as a trigger */
		if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
			elog(ERROR, "not fired by event trigger manager");

		/* Switch memory context */
		contextQuery = AllocSetContextCreate(
						CurrentMemoryContext,
						"pgaudit_func_ddl_command_end temporary context",
						ALLOCSET_DEFAULT_MINSIZE,
						ALLOCSET_DEFAULT_INITSIZE,
						ALLOCSET_DEFAULT_MAXSIZE);
		contextOld = MemoryContextSwitchTo(contextQuery);

		/* Get information about triggered events */
		eventData = (EventTriggerData *) fcinfo->context;

		/* Return objects affected by the (non drop) DDL statement */
		query = "SELECT classid, objid, objsubid, UPPER(object_type), schema,\n"
				"       identity, command\n"
				"  FROM pg_event_trigger_get_creation_commands()";

		/* Attempt to connect */
		result = SPI_connect();

		if (result < 0)
			elog(ERROR, "pg_audit_ddl_command_end: SPI_connect returned %d",
						result);

		/* Execute the query */
		result = SPI_execute(query, true, 0);

		if (result != SPI_OK_SELECT)
			elog(ERROR, "pg_audit_ddl_command_end: SPI_execute returned %d",
						result);

		/* Iterate returned rows */
		spiTupDesc = SPI_tuptable->tupdesc;

		for (row = 0; row < SPI_processed; row++)
		{
			HeapTuple  spiTuple;
			bool	   isNull;

			spiTuple = SPI_tuptable->vals[row];

			/* Supply addition data to current audit event */
			auditEventStack->auditEvent.logStmtLevel =
				GetCommandLogLevel(eventData->parsetree);
			auditEventStack->auditEvent.commandTag =
				nodeTag(eventData->parsetree);
			auditEventStack->auditEvent.command =
				CreateCommandTag(eventData->parsetree);
			auditEventStack->auditEvent.objectName =
				SPI_getvalue(spiTuple, spiTupDesc, 6);
			auditEventStack->auditEvent.objectType =
				SPI_getvalue(spiTuple, spiTupDesc, 4);
			auditEventStack->auditEvent.commandText =
				TextDatumGetCString(
					DirectFunctionCall1(pg_event_trigger_expand_command,
										SPI_getbinval(spiTuple, spiTupDesc,
													  7, &isNull)));

			/* Log the audit event */
			log_audit_event(auditEventStack);
		}

		/* Complete the query */
		SPI_finish();

		/* Switch to the old memory context */
		MemoryContextSwitchTo(contextOld);
		MemoryContextDelete(contextQuery);

		/* No longer in an internal statement */
		internalStatement = false;
	}

	PG_RETURN_NULL();
}

/*
 * Supply additional data for drop statements that have event trigger support.
 */
Datum
pg_audit_sql_drop(PG_FUNCTION_ARGS)
{
	if (auditLogBitmap & LOG_DDL)
	{
		int				  result, row;
		TupleDesc		  spiTupDesc;
		const char		 *query;
		MemoryContext 	  contextQuery;
		MemoryContext 	  contextOld;

		/* This is an internal statement - do not log it */
		internalStatement = true;

		/* Make sure the fuction was fired as a trigger */
		if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
			elog(ERROR, "not fired by event trigger manager");

		/* Switch memory context */
		contextQuery = AllocSetContextCreate(
						CurrentMemoryContext,
						"pgaudit_func_ddl_command_end temporary context",
						ALLOCSET_DEFAULT_MINSIZE,
						ALLOCSET_DEFAULT_INITSIZE,
						ALLOCSET_DEFAULT_MAXSIZE);
		contextOld = MemoryContextSwitchTo(contextQuery);

		/* Return objects affected by the drop statement */
		query = "SELECT classid, objid, objsubid, UPPER(object_type),\n"
				"       schema_name, object_name, object_identity\n"
				"  FROM pg_event_trigger_dropped_objects()";

		/* Attempt to connect */
		result = SPI_connect();

		if (result < 0)
			elog(ERROR, "pg_audit_ddl_drop: SPI_connect returned %d",
						result);

		/* Execute the query */
		result = SPI_execute(query, true, 0);

		if (result != SPI_OK_SELECT)
			elog(ERROR, "pg_audit_ddl_drop: SPI_execute returned %d",
						result);

		/* Iterate returned rows */
		spiTupDesc = SPI_tuptable->tupdesc;

		for (row = 0; row < SPI_processed; row++)
		{
			HeapTuple  spiTuple;
			char *schemaName;

			spiTuple = SPI_tuptable->vals[row];

			auditEventStack->auditEvent.objectType =
				SPI_getvalue(spiTuple, spiTupDesc, 4);
			schemaName = SPI_getvalue(spiTuple, spiTupDesc, 5);

			if (!(pg_strcasecmp(auditEventStack->auditEvent.objectType,
							"TYPE") == 0 ||
				  pg_strcasecmp(schemaName, "pg_toast") == 0))
			{
				auditEventStack->auditEvent.objectName =
						SPI_getvalue(spiTuple, spiTupDesc, 7);

				log_audit_event(auditEventStack);
			}
		}

		/* Complete the query */
		SPI_finish();

		/* Switch to the old memory context */
		MemoryContextSwitchTo(contextOld);
		MemoryContextDelete(contextQuery);

		/* No longer in an internal statement */
		internalStatement = false;
	}

	PG_RETURN_NULL();
}

/*
 * GUC check and assign functions
 */

/*
 * Take a pg_audit.log value such as "read, write, dml", verify that each of the
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
	 * Check that we recognise each token, and add it to the bitmap we're
	 * building up in a newly-allocated uint64 *f.
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
		else if (pg_strcasecmp(token, CLASS_PARAMETER) == 0)
			class = LOG_PARAMETER;
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
			errmsg("pg_audit must be loaded via shared_preload_libraries")));

	/*
	 * pg_audit.role = "audit"
	 *
	 * This variable defines a role to be used for auditing.
	 */
	DefineCustomStringVariable("pg_audit.role",
							   "Enable auditing for role",
							   NULL,
							   &auditRole,
							   "",
							   PGC_SUSET,
							   GUC_NOT_IN_SAMPLE,
							   NULL, NULL, NULL);

	/*
	 * pg_audit.log = "read, write, ddl"
	 *
	 * This variables controls what classes of commands are logged.
	 */
	DefineCustomStringVariable("pg_audit.log",
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
	next_ExecutorStart_hook = ExecutorStart_hook;
	ExecutorStart_hook = pgaudit_ExecutorStart_hook;

	next_ExecutorCheckPerms_hook = ExecutorCheckPerms_hook;
	ExecutorCheckPerms_hook = pgaudit_ExecutorCheckPerms_hook;

	next_ExecutorEnd_hook = ExecutorEnd_hook;
	ExecutorEnd_hook = pgaudit_ExecutorEnd_hook;

	next_ProcessUtility_hook = ProcessUtility_hook;
	ProcessUtility_hook = pgaudit_ProcessUtility_hook;

	next_object_access_hook = object_access_hook;
	object_access_hook = pgaudit_object_access_hook;
}
