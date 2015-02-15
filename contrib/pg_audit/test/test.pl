#!/usr/bin/perl
################################################################################
# test.pl - pgAudit Unit Tests
################################################################################

################################################################################
# Perl includes
################################################################################
use strict;
use warnings;
use Carp;

use Getopt::Long;
use Pod::Usage;
use DBI;
use Cwd qw(abs_path);
use IPC::System::Simple qw(capture);

################################################################################
# Constants
################################################################################
use constant
{
	true  => 1,
	false => 0
};

use constant
{
	CONTEXT_GLOBAL   => 'GLOBAL',
	CONTEXT_DATABASE => 'DATABASE',
	CONTEXT_ROLE	 => 'ROLE'
};

use constant
{
	CLASS			=> 'CLASS',

	CLASS_DDL		=> 'DDL',
	CLASS_FUNCTION	=> 'FUNCTION',
	CLASS_MISC		=> 'MISC',
	CLASS_READ		=> 'READ',
	CLASS_WRITE		=> 'WRITE',

	CLASS_ALL		=> 'ALL',
	CLASS_NONE		=> 'NONE'
};

use constant
{
	COMMAND						=> 'COMMAND',
	COMMAND_LOG					=> 'COMMAND_LOG',

	COMMAND_ANALYZE				=> 'ANALYZE',
	COMMAND_ALTER_AGGREGATE		=> 'ALTER AGGREGATE',
	COMMAND_ALTER_COLLATION		=> 'ALTER COLLATION',
	COMMAND_ALTER_CONVERSION	=> 'ALTER CONVERSION',
	COMMAND_ALTER_DATABASE		=> 'ALTER DATABASE',
	COMMAND_ALTER_ROLE			=> 'ALTER ROLE',
	COMMAND_ALTER_ROLE_SET		=> 'ALTER ROLE SET',
	COMMAND_ALTER_TABLE			=> 'ALTER TABLE',
	COMMAND_ALTER_TABLE_INDEX	=> 'ALTER TABLE INDEX',
	COMMAND_BEGIN				=> 'BEGIN',
	COMMAND_CLOSE				=> 'CLOSE CURSOR',
	COMMAND_COMMIT				=> 'COMMIT',
	COMMAND_COPY				=> 'COPY',
	COMMAND_COPY_TO				=> 'COPY TO',
	COMMAND_COPY_FROM			=> 'COPY FROM',
	COMMAND_CREATE_AGGREGATE	=> 'CREATE AGGREGATE',
	COMMAND_CREATE_COLLATION	=> 'CREATE COLLATION',
	COMMAND_CREATE_CONVERSION	=> 'CREATE CONVERSION',
	COMMAND_CREATE_DATABASE		=> 'CREATE DATABASE',
	COMMAND_CREATE_INDEX		=> 'CREATE INDEX',
	COMMAND_DEALLOCATE			=> 'DEALLOCATE',
	COMMAND_DECLARE_CURSOR		=> 'DECLARE CURSOR',
	COMMAND_DO					=> 'DO',
	COMMAND_DISCARD_ALL			=> 'DISCARD ALL',
	COMMAND_CREATE_FUNCTION		=> 'CREATE FUNCTION',
	COMMAND_CREATE_ROLE			=> 'CREATE ROLE',
	COMMAND_CREATE_SCHEMA		=> 'CREATE SCHEMA',
	COMMAND_CREATE_TABLE		=> 'CREATE TABLE',
	COMMAND_CREATE_TABLE_AS		=> 'CREATE TABLE AS',
	COMMAND_DROP_DATABASE		=> 'DROP DATABASE',
	COMMAND_DROP_SCHEMA			=> 'DROP SCHEMA',
	COMMAND_DROP_TABLE			=> 'DROP TABLE',
	COMMAND_DROP_TABLE_INDEX	=> 'DROP TABLE INDEX',
	COMMAND_DROP_TABLE_TYPE		=> 'DROP TABLE TYPE',
	COMMAND_EXECUTE				=> 'EXECUTE',
	COMMAND_EXECUTE_READ		=> 'EXECUTE READ',
	COMMAND_EXECUTE_WRITE		=> 'EXECUTE WRITE',
	COMMAND_EXECUTE_FUNCTION	=> 'EXECUTE FUNCTION',
	COMMAND_FETCH				=> 'FETCH',
	COMMAND_GRANT				=> 'GRANT',
	COMMAND_INSERT				=> 'INSERT',
	COMMAND_PREPARE				=> 'PREPARE',
	COMMAND_PREPARE_READ		=> 'PREPARE READ',
	COMMAND_PREPARE_WRITE		=> 'PREPARE WRITE',
	COMMAND_REVOKE				=> 'REVOKE',
	COMMAND_SELECT				=> 'SELECT',
	COMMAND_SET					=> 'SET',
	COMMAND_UPDATE				=> 'UPDATE'
};

use constant
{
	TYPE			=> 'TYPE',
	TYPE_NONE		=> '',

	TYPE_FUNCTION	=> 'FUNCTION',
	TYPE_INDEX		=> 'INDEX',
	TYPE_TABLE		=> 'TABLE',
	TYPE_TYPE		=> 'TYPE'
};

use constant
{
	NAME			=> 'NAME'
};

################################################################################
# Command line parameters
################################################################################
my $strPgSqlBin = '../../../../bin/bin';	# Path of PG binaries to use for
											# this test
my $strTestPath = '../../../../data';		# Path where testing will occur
my $iDefaultPort = 6000;					# Default port to run Postgres on
my $bHelp = false;							# Display help
my $bQuiet = false;							# Supress output except for errors
my $bNoCleanup = false;						# Cleanup database on exit

GetOptions ('q|quiet' => \$bQuiet,
			'no-cleanup' => \$bNoCleanup,
			'help' => \$bHelp,
			'pgsql-bin=s' => \$strPgSqlBin,
			'test-path=s' => \$strTestPath)
	or pod2usage(2);

# Display version and exit if requested
if ($bHelp)
{
	print 'pg_audit unit test\n\n';
	pod2usage();

	exit 0;
}

################################################################################
# Global variables
################################################################################
my $hDb;					# Connection to Postgres
my $strLogExpected = '';	# The expected log compared with grepping AUDIT
							# entries from the postgres log.

my $strDatabase = 'postgres';	# Connected database (modified by PgSetDatabase)
my $strUser = 'postgres';		# Connected user (modified by PgSetUser)
my $strAuditRole = 'audit';		# Role to use for auditing

my %oAuditLogHash;				# Hash to store pgaudit.log GUCS
my %oAuditGrantHash;			# Hash to store pgaudit grants

my $strCurrentAuditLog;		# pgaudit.log setting that Postgres was started with
my $strTemporaryAuditLog;	# pgaudit.log setting that was set hot

################################################################################
# Stores the mapping between commands, classes, and types
################################################################################
my %oCommandHash =
(&COMMAND_ANALYZE => {
	&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_ALTER_AGGREGATE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_ALTER_DATABASE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_ALTER_COLLATION => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_ALTER_CONVERSION => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_ALTER_ROLE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_ALTER_ROLE_SET => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE,
		&COMMAND => &COMMAND_ALTER_ROLE},
	&COMMAND_ALTER_TABLE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_TABLE},
	&COMMAND_ALTER_TABLE_INDEX => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_INDEX,
		&COMMAND => &COMMAND_ALTER_TABLE},
	&COMMAND_BEGIN => {&CLASS => &CLASS_MISC, &TYPE => &TYPE_NONE},
	&COMMAND_CLOSE => {&CLASS => &CLASS_MISC, &TYPE => &TYPE_NONE},
	&COMMAND_COMMIT => {&CLASS => &CLASS_MISC, &TYPE => &TYPE_NONE},
	&COMMAND_COPY_FROM => {&CLASS => &CLASS_WRITE, &TYPE => &TYPE_NONE,
		&COMMAND => &COMMAND_COPY},
	&COMMAND_COPY_TO => {&CLASS => &CLASS_READ, &TYPE => &TYPE_NONE,
		&COMMAND => &COMMAND_COPY},
	&COMMAND_CREATE_AGGREGATE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_CREATE_CONVERSION => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_CREATE_COLLATION => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_CREATE_DATABASE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_CREATE_INDEX => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_INDEX},
	&COMMAND_DEALLOCATE => {&CLASS => &CLASS_MISC, &TYPE => &TYPE_NONE},
	&COMMAND_DECLARE_CURSOR => {&CLASS => &CLASS_READ, &TYPE => &TYPE_NONE},
	&COMMAND_DO => {&CLASS => &CLASS_FUNCTION, &TYPE => &TYPE_NONE},
	&COMMAND_DISCARD_ALL => {&CLASS => &CLASS_MISC, &TYPE => &TYPE_NONE},
	&COMMAND_CREATE_FUNCTION => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_CREATE_ROLE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_CREATE_SCHEMA => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_CREATE_TABLE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_TABLE},
	&COMMAND_CREATE_TABLE_AS => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_TABLE},
	&COMMAND_DROP_DATABASE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_DROP_SCHEMA => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_DROP_TABLE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_TABLE},
	&COMMAND_DROP_TABLE_INDEX => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_INDEX,
		&COMMAND => &COMMAND_DROP_TABLE},
	&COMMAND_DROP_TABLE_TYPE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_TYPE,
		&COMMAND => &COMMAND_DROP_TABLE},
	&COMMAND_EXECUTE_READ => {&CLASS => &CLASS_READ, &TYPE => &TYPE_NONE,
		&COMMAND => &COMMAND_EXECUTE},
	&COMMAND_EXECUTE_WRITE => {&CLASS => &CLASS_WRITE, &TYPE => &TYPE_NONE,
		&COMMAND => &COMMAND_EXECUTE},
	&COMMAND_EXECUTE_FUNCTION => {&CLASS => &CLASS_FUNCTION,
		&TYPE => &TYPE_FUNCTION, &COMMAND => &COMMAND_EXECUTE},
	&COMMAND_FETCH => {&CLASS => &CLASS_MISC, &TYPE => &TYPE_NONE},
	&COMMAND_GRANT => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_PREPARE_READ => {&CLASS => &CLASS_READ, &TYPE => &TYPE_NONE,
		&COMMAND => &COMMAND_PREPARE},
	&COMMAND_PREPARE_WRITE => {&CLASS => &CLASS_WRITE, &TYPE => &TYPE_NONE,
		&COMMAND => &COMMAND_PREPARE},
	&COMMAND_INSERT => {&CLASS => &CLASS_WRITE, &TYPE => &TYPE_NONE},
	&COMMAND_REVOKE => {&CLASS => &CLASS_DDL, &TYPE => &TYPE_NONE},
	&COMMAND_SELECT => {&CLASS => &CLASS_READ, &TYPE => &TYPE_NONE},
	&COMMAND_SET => {&CLASS => &CLASS_MISC, &TYPE => &TYPE_NONE},
	&COMMAND_UPDATE => {&CLASS => &CLASS_WRITE, &TYPE => &TYPE_NONE}
);

################################################################################
# CommandExecute
################################################################################
sub CommandExecute
{
	my $strCommand = shift;
	my $bSuppressError = shift;

	# Set default
	$bSuppressError = defined($bSuppressError) ? $bSuppressError : false;

	# Run the command
	my $iResult = system($strCommand);

	if ($iResult != 0 && !$bSuppressError)
	{
		confess "command '${strCommand}' failed with error ${iResult}";
	}
}

################################################################################
# log
################################################################################
sub log
{
	my $strMessage = shift;
	my $bError = shift;

	# Set default
	$bError = defined($bError) ? $bError : false;

	if (!$bQuiet)
	{
		print "${strMessage}\n";
	}

	if ($bError)
	{
		exit 1;
	}
}

################################################################################
# ArrayToString
################################################################################
sub ArrayToString
{
	my @stryArray = @_;

	my $strResult = '';

	for (my $iIndex = 0; $iIndex < @stryArray; $iIndex++)
	{
		if ($iIndex != 0)
		{
			$strResult .= ', ';
		}

		$strResult .= $stryArray[$iIndex];
	}

	return $strResult;
}

################################################################################
# BuildModule
################################################################################
sub BuildModule
{
	capture('cd ..;make');
	CommandExecute("cp ../pg_audit.so" .
	               " ${strPgSqlBin}/../lib/postgresql");
	CommandExecute("cp ../pg_audit.control" .
	               " ${strPgSqlBin}/../share/postgresql/extension");
	CommandExecute("cp ../pg_audit--1.0.0.sql" .
	               " ${strPgSqlBin}/../share/postgresql/extension");
}

################################################################################
# PgConnect
################################################################################
sub PgConnect
{
	my $iPort = shift;

	# Set default
	$iPort = defined($iPort) ? $iPort : $iDefaultPort;

	# Log Connection
	&log("   DB: connect user ${strUser}, database ${strDatabase}");

	# Disconnect user session
	PgDisconnect();

	# Connect to the db
	$hDb = DBI->connect("dbi:Pg:dbname=${strDatabase};port=${iPort};host=/tmp",
						$strUser, undef,
						{AutoCommit => 1, RaiseError => 1});
}

################################################################################
# PgDisconnect
################################################################################
sub PgDisconnect
{
	# Connect to the db (whether it is local or remote)
	if (defined($hDb))
	{
		$hDb->disconnect;
		undef($hDb);
	}
}

################################################################################
# PgExecute
################################################################################
sub PgExecute
{
	my $strSql = shift;

	# Log the statement
	&log("  SQL: ${strSql}");

	# Execute the statement
	my $hStatement = $hDb->prepare($strSql);

	$hStatement->execute();
	$hStatement->finish();
}

################################################################################
# PgExecuteOnly
################################################################################
sub PgExecuteOnly
{
	my $strSql = shift;

	# Log the statement
	&log("  SQL: ${strSql}");

	# Execute the statement
	$hDb->do($strSql);
}

################################################################################
# PgSetDatabase
################################################################################
sub PgSetDatabase
{
	my $strDatabaseParam = shift;

	# Stop and start the database to reset pgconf entries
	PgStop();
	PgStart();

	# Execute the statement
	$strDatabase = $strDatabaseParam;
	PgConnect();
}

################################################################################
# PgSetUser
################################################################################
sub PgSetUser
{
	my $strUserParam = shift;

	$strUser = $strUserParam;

	# Stop and start the database to reset pgconf entries
	if ((defined($strTemporaryAuditLog) && !defined($strCurrentAuditLog)) ||
		(defined($strCurrentAuditLog) && !defined($strTemporaryAuditLog)) ||
		$strCurrentAuditLog ne $strTemporaryAuditLog)
	{
		$strCurrentAuditLog = $strTemporaryAuditLog;

		PgStop();
		PgStart();
	}
	else
	{
		# Execute the statement
		PgConnect();
	}
}

################################################################################
# SaveString
################################################################################
sub SaveString
{
	my $strFile = shift;
	my $strString = shift;

	# Open the file for writing
	my $hFile;

	open($hFile, '>', $strFile)
		or confess "unable to open ${strFile}";

	if ($strString ne '')
	{
		syswrite($hFile, $strString)
			or confess "unable to write to ${strFile}: $!";
	}

	close($hFile);
}

################################################################################
# PgLogExecute
################################################################################
sub PgLogExecute
{
	my $strCommand = shift;
	my $strSql = shift;
	my $oData = shift;
	my $bExecute = shift;
	my $bWait = shift;
	my $bLogSql = shift;

	# Set defaults
	$bExecute = defined($bExecute) ? $bExecute : true;
	$bWait = defined($bWait) ? $bWait : true;
	$bLogSql = defined($bLogSql) ? $bLogSql : true;

	if ($bExecute)
	{
		PgExecuteOnly($strSql);
	}

	PgLogExpect($strCommand, $bLogSql ? $strSql : '', $oData);

	if ($bWait)
	{
		PgLogWait();
	}
}

################################################################################
# PgLogExpect
################################################################################
sub PgLogExpect
{
	my $strCommand = shift;
	my $strSql = shift;
	my $oData = shift;

	# If oData is false then no logging
	if (defined($oData) && ref($oData) eq '' && !$oData)
	{
		return;
	}

	# Log based on session
	if (PgShouldLog($strCommand))
	{
		# Make sure class is defined
		my $strClass = $oCommandHash{$strCommand}{&CLASS};

		if (!defined($strClass))
		{
			confess "class is not defined for command ${strCommand}";
		}

		# Make sure object type is defined
		my $strObjectType = $oCommandHash{$strCommand}{&TYPE};

		if (!defined($strObjectType))
		{
			confess "object type is not defined for command ${strCommand}";
		}

		# Check for command override
		my $strCommandLog = $strCommand;

		if ($oCommandHash{$strCommand}{&COMMAND})
		{
			$strCommandLog = $oCommandHash{$strCommand}{&COMMAND};
		}

		my $strObjectName = '';

		if (defined($oData) && ref($oData) ne 'ARRAY')
		{
			$strObjectName = $oData;
		}

		my $strLog .= "SESSION,${strClass},${strCommandLog}," .
					  "${strObjectType},${strObjectName},${strSql}";
		&log("AUDIT: ${strLog}");

		$strLogExpected .= "${strLog}\n";
	}

	# Log based on grants
	if (ref($oData) eq 'ARRAY' && ($strCommand eq COMMAND_SELECT ||
		$oCommandHash{$strCommand}{&CLASS} eq CLASS_WRITE))
	{
		foreach my $oTableHash (@{$oData})
		{
			my $strObjectName = ${$oTableHash}{&NAME};
			my $strCommandLog = ${$oTableHash}{&COMMAND};

			if (defined($oAuditGrantHash{$strAuditRole}
										{$strObjectName}{$strCommandLog}))
			{
				my $strCommandLog = defined(${$oTableHash}{&COMMAND_LOG}) ?
					${$oTableHash}{&COMMAND_LOG} : $strCommandLog;
				my $strClass = $oCommandHash{$strCommandLog}{&CLASS};
				my $strObjectType = ${$oTableHash}{&TYPE};

				my $strLog .= "OBJECT,${strClass},${strCommandLog}," .
							  "${strObjectType},${strObjectName},${strSql}";
				&log("AUDIT: ${strLog}");

				$strLogExpected .= "${strLog}\n";
			}
		}

		$oData = undef;
	}
}

################################################################################
# PgShouldLog
################################################################################
sub PgShouldLog
{
	my $strCommand = shift;

	# Make sure class is defined
	my $strClass = $oCommandHash{$strCommand}{&CLASS};

	if (!defined($strClass))
	{
		confess "class is not defined for command ${strCommand}";
	}

	# Check logging for the role
	my $bLog = undef;

	if (defined($oAuditLogHash{&CONTEXT_ROLE}{$strUser}))
	{
		$bLog = $oAuditLogHash{&CONTEXT_ROLE}{$strUser}{$strClass};
	}

	# Else check logging for the db
	elsif (defined($oAuditLogHash{&CONTEXT_DATABASE}{$strDatabase}))
	{
		$bLog = $oAuditLogHash{&CONTEXT_DATABASE}{$strDatabase}{$strClass};
	}

	# Else check logging for global
	elsif (defined($oAuditLogHash{&CONTEXT_GLOBAL}{&CONTEXT_GLOBAL}))
	{
		$bLog = $oAuditLogHash{&CONTEXT_GLOBAL}{&CONTEXT_GLOBAL}{$strClass};
	}

	return defined($bLog) ? true : false;
}

################################################################################
# PgLogWait
################################################################################
sub PgLogWait
{
	my $strLogActual;

	# Run in an eval block since grep returns 1 when nothing was found
	eval
	{
		$strLogActual = capture("grep 'LOG:  AUDIT: '" .
								" ${strTestPath}/postgresql.log");
	};

	# If an error was returned, continue if it was 1, otherwise confess
	if ($@)
	{
		my $iExitStatus = $? >> 8;

		if ($iExitStatus != 1)
		{
			confess "grep returned ${iExitStatus}";
		}

		$strLogActual = '';
	}

	# Strip the AUDIT and timestamp from the actual log
	$strLogActual =~ s/prefix LOG:  AUDIT\: //g;

	# Save the logs
	SaveString("${strTestPath}/audit.actual", $strLogActual);
	SaveString("${strTestPath}/audit.expected", $strLogExpected);

	CommandExecute("diff ${strTestPath}/audit.expected" .
				   " ${strTestPath}/audit.actual");
}

################################################################################
# PgDrop
################################################################################
sub PgDrop
{
	my $strPath = shift;

	# Set default
	$strPath = defined($strPath) ? $strPath : $strTestPath;

	# Stop the cluster
	PgStop(true, $strPath);

	# Remove the directory
	CommandExecute("rm -rf ${strTestPath}");
}

################################################################################
# PgCreate
################################################################################
sub PgCreate
{
	my $strPath = shift;

	# Set default
	$strPath = defined($strPath) ? $strPath : $strTestPath;

	CommandExecute("${strPgSqlBin}/initdb -D ${strPath} -U ${strUser}" .
				   ' -A trust > /dev/null');
}

################################################################################
# PgStop
################################################################################
sub PgStop
{
	my $bImmediate = shift;
	my $strPath = shift;

	# Set default
	$strPath = defined($strPath) ? $strPath : $strTestPath;
	$bImmediate = defined($bImmediate) ? $bImmediate : false;

	# Disconnect user session
	PgDisconnect();

	# If postmaster process is running then stop the cluster
	if (-e $strPath . '/postmaster.pid')
	{
		CommandExecute("${strPgSqlBin}/pg_ctl stop -D ${strPath} -w -s -m " .
					  ($bImmediate ? 'immediate' : 'fast'));
	}
}

################################################################################
# PgStart
################################################################################
sub PgStart
{
	my $iPort = shift;
	my $strPath = shift;

	# Set default
	$iPort = defined($iPort) ? $iPort : $iDefaultPort;
	$strPath = defined($strPath) ? $strPath : $strTestPath;

	# Make sure postgres is not running
	if (-e $strPath . '/postmaster.pid')
	{
		confess "${strPath}/postmaster.pid exists, cannot start";
	}

	# Start the cluster
	CommandExecute("${strPgSqlBin}/pg_ctl start -o \"" .
				   "-c port=${iPort}" .
				   " -c unix_socket_directories='/tmp'" .
				   " -c shared_preload_libraries='pg_audit'" .
				   " -c log_min_messages=debug1" .
				   " -c log_line_prefix='prefix '" .
				   # " -c log_destination='stderr,csvlog'" .
				   # " -c logging_collector=on" .
				   (defined($strCurrentAuditLog) ?
					   " -c pgaudit.log='${strCurrentAuditLog}'" : '') .
				   " -c pgaudit.role='${strAuditRole}'" .
				   " -c log_connections=on" .
				   "\" -D ${strPath} -l ${strPath}/postgresql.log -w -s");

	# Connect user session
	PgConnect();
}

################################################################################
# PgAuditLogSet
################################################################################
sub PgAuditLogSet
{
	my $strContext = shift;
	my $strName = shift;
	my @stryClass = @_;

	# Create SQL to set the GUC
	my $strCommand;
	my $strSql;

	if ($strContext eq CONTEXT_GLOBAL)
	{
		$strCommand = COMMAND_SET;
		$strSql = "set pgaudit.log = '" .
				  ArrayToString(@stryClass) . "'";
		$strTemporaryAuditLog = ArrayToString(@stryClass);
	}
	elsif ($strContext eq CONTEXT_ROLE)
	{
		$strCommand = COMMAND_ALTER_ROLE_SET;
		$strSql = "alter role ${strName} set pgaudit.log = '" .
				  ArrayToString(@stryClass) . "'";
	}
	else
	{
		confess "unable to set pgaudit.log for context ${strContext}";
	}

	# Reset the audit log
	if ($strContext eq CONTEXT_GLOBAL)
	{
		delete($oAuditLogHash{$strContext});
		$strName = CONTEXT_GLOBAL;
	}
	else
	{
		delete($oAuditLogHash{$strContext}{$strName});
	}

	# Store all the classes in the hash and build the GUC
	foreach my $strClass (@stryClass)
	{
		if ($strClass eq CLASS_ALL)
		{
			$oAuditLogHash{$strContext}{$strName}{&CLASS_DDL} = true;
			$oAuditLogHash{$strContext}{$strName}{&CLASS_FUNCTION} = true;
			$oAuditLogHash{$strContext}{$strName}{&CLASS_MISC} = true;
			$oAuditLogHash{$strContext}{$strName}{&CLASS_READ} = true;
			$oAuditLogHash{$strContext}{$strName}{&CLASS_WRITE} = true;
		}

		if (index($strClass, '-') == 0)
		{
			$strClass = substr($strClass, 1);

			delete($oAuditLogHash{$strContext}{$strName}{$strClass});
		}
		else
		{
			$oAuditLogHash{$strContext}{$strName}{$strClass} = true;
		}
	}

	PgLogExecute($strCommand, $strSql);
}

################################################################################
# PgAuditGrantSet
################################################################################
sub PgAuditGrantSet
{
	my $strRole = shift;
	my $strPrivilege = shift;
	my $strObject = shift;
	my $strColumn = shift;

	# Create SQL to set the grant
	PgLogExecute(COMMAND_GRANT, "grant " . lc(${strPrivilege}) .
								(defined($strColumn) ? " (${strColumn})" : '') .
								" on ${strObject} to ${strRole}");

	$oAuditGrantHash{$strRole}{$strObject}{$strPrivilege} = true;
}

################################################################################
# PgAuditGrantReset
################################################################################
sub PgAuditGrantReset
{
	my $strRole = shift;
	my $strPrivilege = shift;
	my $strObject = shift;
	my $strColumn = shift;

	# Create SQL to set the grant
	PgLogExecute(COMMAND_REVOKE, "revoke " . lc(${strPrivilege}) .
				 (defined($strColumn) ? " (${strColumn})" : '') .
				 " on ${strObject} from ${strRole}");

	delete($oAuditGrantHash{$strRole}{$strObject}{$strPrivilege});
}

################################################################################
# Main
################################################################################
my @oyTable; # Store table info for select, insert, update, delete

# Drop the old cluster, build the code, and create a new cluster
PgDrop();
BuildModule();
PgCreate();
PgStart();

PgExecute("create extension pg_audit");

# Create test users and the audit role
PgExecute("create user user1");
PgExecute("create user user2");
PgExecute("create role ${strAuditRole}");

PgAuditLogSet(CONTEXT_GLOBAL, undef, (CLASS_DDL));

PgAuditLogSet(CONTEXT_ROLE, 'user2', (CLASS_READ, CLASS_WRITE));

# User1 follows the global log settings
PgSetUser('user1');
PgLogExecute(COMMAND_CREATE_TABLE, 'create table test (id int)', 'public.test');
PgLogExecute(COMMAND_SELECT, 'select * from test');

PgLogExecute(COMMAND_DROP_TABLE, 'drop table test', 'public.test');

PgSetUser('user2');
PgLogExecute(COMMAND_CREATE_TABLE,
             'create table test2 (id int)', 'public.test2');
PgAuditGrantSet($strAuditRole, &COMMAND_SELECT, 'public.test2');
PgLogExecute(COMMAND_CREATE_TABLE,
             'create table test3 (id int)', 'public.test2');

# Catalog select should not log
PgLogExecute(COMMAND_SELECT, 'select * from pg_class limit 1',
							   false);

# Multi-table select
@oyTable = ({&NAME => 'public.test3', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_SELECT},
			{&NAME => 'public.test2', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_SELECT});
PgLogExecute(COMMAND_SELECT, 'select * from test3, test2',
							   \@oyTable);

# Various CTE combinations
PgAuditGrantSet($strAuditRole, &COMMAND_INSERT, 'public.test3');

@oyTable = ({&NAME => 'public.test3', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_INSERT},
			{&NAME => 'public.test2', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_SELECT});
PgLogExecute(COMMAND_INSERT,
			 'with cte as (select id from test2)' .
			 ' insert into test3 select id from cte',
			 \@oyTable);

@oyTable = ({&NAME => 'public.test2', &TYPE => &TYPE_TABLE,
             &COMMAND => &COMMAND_INSERT},
			{&NAME => 'public.test3', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_INSERT});
PgLogExecute(COMMAND_INSERT,
			 'with cte as (insert into test3 values (1) returning id)' .
			 ' insert into test2 select id from cte',
			 \@oyTable);

PgAuditGrantSet($strAuditRole, &COMMAND_UPDATE, 'public.test2');

@oyTable = ({&NAME => 'public.test3', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_INSERT},
			{&NAME => 'public.test2', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_UPDATE});
PgLogExecute(COMMAND_INSERT,
             'with cte as (update test2 set id = 1 returning id)' .
			 ' insert into test3 select id from cte',
			 \@oyTable);

@oyTable = ({&NAME => 'public.test3', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_UPDATE},
			{&NAME => 'public.test2', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_INSERT},
			{&NAME => 'public.test2', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_SELECT, &COMMAND_LOG => &COMMAND_INSERT});
PgLogExecute(COMMAND_UPDATE,
			 'with cte as (insert into test2 values (1) returning id)' .
			 ' update test3 set id = cte.id' .
			 ' from cte where test3.id <> cte.id',
			 \@oyTable);

PgSetUser('postgres');
PgAuditLogSet(CONTEXT_ROLE, 'user2', (CLASS_NONE));
PgSetUser('user2');

# Column-based audits
PgLogExecute(COMMAND_CREATE_TABLE,
			 'create table test4 (id int, name text)', 'public.test4');
PgAuditGrantSet($strAuditRole, COMMAND_SELECT, 'public.test4', 'name');
PgAuditGrantSet($strAuditRole, COMMAND_UPDATE, 'public.test4', 'id');
PgAuditGrantSet($strAuditRole, COMMAND_INSERT, 'public.test4', 'name');

# Select
@oyTable = ();
PgLogExecute(COMMAND_SELECT, 'select id from public.test4',
							  \@oyTable);

@oyTable = ({&NAME => 'public.test4', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_SELECT});
PgLogExecute(COMMAND_SELECT, 'select name from public.test4',
							  \@oyTable);

# Insert
@oyTable = ();
PgLogExecute(COMMAND_INSERT, 'insert into public.test4 (id) values (1)',
							   \@oyTable);

@oyTable = ({&NAME => 'public.test4', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_INSERT});
PgLogExecute(COMMAND_INSERT, "insert into public.test4 (name) values ('test')",
							  \@oyTable);

# Update
@oyTable = ();
PgLogExecute(COMMAND_UPDATE, "update public.test4 set name = 'foo'",
							   \@oyTable);

@oyTable = ({&NAME => 'public.test4', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_UPDATE});
PgLogExecute(COMMAND_UPDATE, "update public.test4 set id = 1",
							  \@oyTable);

@oyTable = ({&NAME => 'public.test4', &TYPE => &TYPE_TABLE,
            &COMMAND => &COMMAND_SELECT, &COMMAND_LOG => &COMMAND_UPDATE});
PgLogExecute(COMMAND_UPDATE,
			 "update public.test4 set name = 'foo' where name = 'bar'",
			 \@oyTable);

# Drop test tables
PgLogExecute(COMMAND_DROP_TABLE, "drop table test2", 'public.test2');
PgLogExecute(COMMAND_DROP_TABLE, "drop table test3", 'public.test3');
PgLogExecute(COMMAND_DROP_TABLE, "drop table test4", 'public.test4');


# Make sure there are no more audit events pending in the postgres log
PgLogWait();

# Now create some email friendly tests.  These first tests are session logging
# only.
PgSetUser('postgres');

&log("\nExamples:");

&log("\nSession Audit:\n");

PgAuditLogSet(CONTEXT_GLOBAL, undef, (CLASS_DDL, CLASS_READ));
PgSetUser('user1');

PgLogExecute(COMMAND_CREATE_TABLE,
			 'create table account (id int, name text, password text,' .
			 ' description text)', 'public.account');
PgLogExecute(COMMAND_SELECT,
			 'select * from account');
PgLogExecute(COMMAND_INSERT,
			 "insert into account (id, name, password, description)" .
			 " values (1, 'user1', 'HASH1', 'blah, blah')");
&log("AUDIT: <nothing logged>");

# Now tests for object logging
&log("\nObject Audit:\n");

PgSetUser('postgres');
PgAuditLogSet(CONTEXT_GLOBAL, undef, (CLASS_NONE));
PgExecute("set pgaudit.role = 'audit'");
PgSetUser('user1');

PgAuditGrantSet($strAuditRole, &COMMAND_SELECT, 'public.account', 'password');

@oyTable = ();
PgLogExecute(COMMAND_SELECT, 'select id, name from account',
							  \@oyTable);
&log("AUDIT: <nothing logged>");

@oyTable = ({&NAME => 'public.account', &TYPE => &TYPE_TABLE,
             &COMMAND => &COMMAND_SELECT});
PgLogExecute(COMMAND_SELECT, 'select password from account',
							  \@oyTable);

PgAuditGrantSet($strAuditRole, &COMMAND_UPDATE,
                'public.account', 'name, password');

@oyTable = ();
PgLogExecute(COMMAND_UPDATE, "update account set description = 'yada, yada'",
							  \@oyTable);
&log("AUDIT: <nothing logged>");

@oyTable = ({&NAME => 'public.account', &TYPE => &TYPE_TABLE,
             &COMMAND => &COMMAND_UPDATE});
PgLogExecute(COMMAND_UPDATE, "update account set password = 'HASH2'",
							  \@oyTable);

# Now tests for session/object logging
&log("\nSession/Object Audit:\n");

PgSetUser('postgres');
PgAuditLogSet(CONTEXT_ROLE, 'user1', (CLASS_READ, CLASS_WRITE));
PgSetUser('user1');

PgLogExecute(COMMAND_CREATE_TABLE,
			 'create table account_role_map (account_id int, role_id int)',
			 'public.account_role_map');
PgAuditGrantSet($strAuditRole, &COMMAND_SELECT, 'public.account_role_map');

@oyTable = ({&NAME => 'public.account', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_SELECT},
			{&NAME => 'public.account_role_map', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_SELECT});
PgLogExecute(COMMAND_SELECT,
			 'select account.password, account_role_map.role_id from account' .
			 ' inner join account_role_map' .
			 ' on account.id = account_role_map.account_id',
			 \@oyTable);

@oyTable = ({&NAME => 'public.account', &TYPE => &TYPE_TABLE,
             &COMMAND => &COMMAND_SELECT});
PgLogExecute(COMMAND_SELECT, 'select password from account',
							  \@oyTable);

@oyTable = ();
PgLogExecute(COMMAND_UPDATE, "update account set description = 'yada, yada'",
							  \@oyTable);
&log("AUDIT: <nothing logged>");

@oyTable = ({&NAME => 'public.account', &TYPE => &TYPE_TABLE,
             &COMMAND => &COMMAND_SELECT, &COMMAND_LOG => &COMMAND_UPDATE});
PgLogExecute(COMMAND_UPDATE,
			 "update account set description = 'yada, yada'" .
			 " where password = 'HASH2'",
			 \@oyTable);

@oyTable = ({&NAME => 'public.account', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_UPDATE});
PgLogExecute(COMMAND_UPDATE, "update account set password = 'HASH2'",
							  \@oyTable);

# Test all sql commands
&log("\nExhaustive Command Tests:\n");

PgSetUser('postgres');

PgAuditLogSet(CONTEXT_GLOBAL, undef, (CLASS_ALL));
PgLogExecute(COMMAND_SET, "set pgaudit.role = 'audit'");

PgLogExecute(COMMAND_DO, "do \$\$\ begin raise notice 'test'; end; \$\$;");
PgLogExecute(COMMAND_CREATE_SCHEMA, "create schema test");

# Test COPY
PgLogExecute(COMMAND_COPY_TO,
			 "COPY pg_class to '" . abs_path($strTestPath) . "/class.out'");
PgLogExecute(COMMAND_CREATE_TABLE_AS,
			 "CREATE TABLE test.pg_class as select * from pg_class",
			 'test.pg_class', true, false);
PgLogExecute(COMMAND_INSERT,
			 "CREATE TABLE test.pg_class as select * from pg_class",
			 undef, false, true);
PgLogExecute(COMMAND_INSERT,
			 "COPY test.pg_class from '" . abs_path($strTestPath) .
			 "/class.out'", undef, true, false);
PgLogExecute(COMMAND_COPY_FROM,
			 "COPY test.pg_class from '" . abs_path($strTestPath) .
			 "/class.out'", undef, false, true);

# Test prepared SELECT
PgLogExecute(COMMAND_PREPARE_READ,
			 'PREPARE pgclassstmt (oid) as select *' .
			 ' from pg_class where oid = $1');
PgLogExecute(COMMAND_EXECUTE_READ,
			 'EXECUTE pgclassstmt (1)');
PgLogExecute(COMMAND_DEALLOCATE,
			 'DEALLOCATE pgclassstmt');

# Test cursor
PgLogExecute(COMMAND_BEGIN,
			 'BEGIN');
PgLogExecute(COMMAND_DECLARE_CURSOR,
		     'DECLARE ctest SCROLL CURSOR FOR SELECT * FROM pg_class');
PgLogExecute(COMMAND_FETCH,
			 'FETCH NEXT FROM ctest');
PgLogExecute(COMMAND_CLOSE,
			 'CLOSE ctest');
PgLogExecute(COMMAND_COMMIT,
			 'COMMIT');

# Test prepared INSERT
PgLogExecute(COMMAND_CREATE_TABLE,
			 'create table test.test_insert (id int)', 'test.test_insert');
PgLogExecute(COMMAND_PREPARE_WRITE,
			 'PREPARE pgclassstmt (oid) as insert' .
			 ' into test.test_insert (id) values ($1)');
PgLogExecute(COMMAND_INSERT,
			 'EXECUTE pgclassstmt (1)', undef, true, false);
PgLogExecute(COMMAND_EXECUTE_WRITE,
			 'EXECUTE pgclassstmt (1)', undef, false, true);

# Create a table with a primary key
PgLogExecute(COMMAND_CREATE_TABLE,
			 'create table test (id int primary key, name text,' .
			 'description text)',
			 'public.test', true, false);
PgLogExecute(COMMAND_CREATE_INDEX,
			 'create table test (id int primary key, name text,' .
			 'description text)',
			 'public.test_pkey', false, true);
PgLogExecute(COMMAND_ANALYZE, 'analyze test');

# Grant select to public - this should have no affect on auditing
PgLogExecute(COMMAND_GRANT, 'grant select on public.test to public');
PgLogExecute(COMMAND_SELECT, 'select * from test');

# Now grant select to audit and it should be logged
PgAuditGrantSet($strAuditRole, &COMMAND_SELECT, 'public.test');
@oyTable = ({&NAME => 'public.test', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_SELECT});
PgLogExecute(COMMAND_SELECT, 'select * from test', \@oyTable);

# Check columns granted to public and make sure they do not log
PgAuditGrantReset($strAuditRole, &COMMAND_SELECT, 'public.test');
PgLogExecute(COMMAND_GRANT, 'grant select (name) on public.test to public');
PgLogExecute(COMMAND_SELECT, 'select * from test');
PgLogExecute(COMMAND_SELECT, 'select from test');

# Now set grant to a specific column to audit and make sure it logs
# Make sure the the converse is true
PgAuditGrantSet($strAuditRole, &COMMAND_SELECT, 'public.test',
				'name, description');
PgLogExecute(COMMAND_SELECT, 'select id from test');

@oyTable = ({&NAME => 'public.test', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_SELECT});
PgLogExecute(COMMAND_SELECT, 'select name from test', \@oyTable);

PgLogExecute(COMMAND_ALTER_TABLE,
			 'alter table test drop description', 'public.test');
@oyTable = ({&NAME => 'public.test', &TYPE => &TYPE_TABLE,
			 &COMMAND => &COMMAND_SELECT});
PgLogExecute(COMMAND_SELECT, 'select from test', \@oyTable);

PgLogExecute(COMMAND_ALTER_TABLE,
			 'alter table test rename to test2', 'public.test');
PgLogExecute(COMMAND_ALTER_TABLE,
			 'alter table test2 set schema test', 'public.test2', true, false);
PgLogExecute(COMMAND_ALTER_TABLE_INDEX, 'alter table test2 set schema test',
										'public.test_pkey', false, true);
PgLogExecute(COMMAND_ALTER_TABLE, 'alter table test.test2 add description text',
								  'test.test2');
PgLogExecute(COMMAND_ALTER_TABLE, 'alter table test.test2 drop description',
								  'test.test2');
PgLogExecute(COMMAND_DROP_TABLE_INDEX, 'drop table test.test2',
									   'test.test_pkey', false, false);
PgLogExecute(COMMAND_DROP_TABLE, 'drop table test.test2',
								 'test.test2', true, true);

PgLogExecute(COMMAND_CREATE_FUNCTION, 'CREATE FUNCTION int_add(a int, b int)' .
									  ' returns int as $$ begin return a + b;' .
									  ' end $$language plpgsql');
PgLogExecute(COMMAND_EXECUTE_FUNCTION, "select int_add(1, 1)",
									   'public.int_add');

PgLogExecute(COMMAND_CREATE_AGGREGATE, "CREATE AGGREGATE sum_test (int)" .
							" (sfunc = int_add, stype = int, initcond = 0)");
PgLogExecute(COMMAND_ALTER_AGGREGATE,
			 "ALTER AGGREGATE sum_test (int) rename to sum_test2");

PgLogExecute(COMMAND_CREATE_COLLATION,
			 "CREATE COLLATION collation_test FROM \"de_DE\"");
PgLogExecute(COMMAND_ALTER_COLLATION,
			 "ALTER COLLATION collation_test rename to collation_test2");

PgLogExecute(COMMAND_CREATE_CONVERSION,
			 "CREATE CONVERSION conversion_test FOR 'SQL_ASCII' TO".
			 " 'MULE_INTERNAL' FROM ascii_to_mic");
PgLogExecute(COMMAND_ALTER_CONVERSION,
			 "ALTER CONVERSION conversion_test rename to conversion_test2");

PgLogExecute(COMMAND_CREATE_DATABASE, "CREATE DATABASE database_test");
PgLogExecute(COMMAND_ALTER_DATABASE,
			 "ALTER DATABASE database_test rename to database_test2");
PgLogExecute(COMMAND_DROP_DATABASE, "DROP DATABASE database_test2");

# Make sure there are no more audit events pending in the postgres log
PgLogWait();

# Stop the database
if (!$bNoCleanup)
{
	PgDrop();
}