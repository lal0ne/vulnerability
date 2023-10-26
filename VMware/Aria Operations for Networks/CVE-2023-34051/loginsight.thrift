struct RepoImportCommand {
    1: string path;
    2: i32 interval;
    3: bool monitor;
    4: string parserName;
    5: string inclusion;
    6: string exclusion
}

struct ShutdownCommand {
    1: bool immediately;
    2: bool waitForQueued
}

struct RestartCommand {
    1: bool waitForQueued
}

struct PhoneHomeFeedbackCommand {
    1: bool enable
}

struct HostSyncCommand {
    1: string ntpModeAttributeString
}

struct NtpSyncCommand {
    1: bool test;
    2: list<string> ntpServers
}

struct SupportBundleCommand {
    1: string uuid
}

struct PakUpgradeCommand {
    1: string fileName;
    2: bool eulaOnly;
    3: string outputFile;
    4: bool outputOnly;
    5: string locale;
    6: bool forceInstall
}

struct RemotePakDownloadCommand {
    1: string sourceNodeToken;
    2: string requestUrl;
    3: string fileName
}

struct ConfigLolCommand {
    1: string operation;
    2: string destination;
    3: string protocol;
    4: string port;
    5: string force
}

struct CommandWithTimeout {
    1: Command command;
    2: i64 timeoutMillis
}

struct Command {
    1: i32 commandType;
    2: RepoImportCommand repoImportCommand;
    3: ShutdownCommand shutdownCommand;
    4: RestartCommand restartCommand;
    5: PhoneHomeFeedbackCommand phoneHomeFeedbackCommand;
    6: HostSyncCommand hostSyncCommand;
    7: NtpSyncCommand ntpSyncCommand;
    8: SupportBundleCommand supportBundleCommand;
    9: PakUpgradeCommand pakUpgradeCommand;
    10: RemotePakDownloadCommand remotePakDownloadCommand;
    11: ConfigLolCommand configLolCommand;

}

struct CommandStatusWithHandle {
    1: CommandStatus commandStatus;
    2: CommandHandle commandHandle
}

struct CommandStatus {
    1: i32 commandStatusType;
    2: QueuedCommandStatus queuedCommandStatus;
    3: RunningCommandStatus runningCommandStatus;
    4: ExitedCommandStatus exitedCommandStatus
}

struct CommandHandle {
    1: i64 commandHandle;
    2: string error
}

struct QueuedCommandStatus {
    1: Command command;
    2: Timestamp timeRequested
}

struct RunningCommandStatus {
    1: Command command;
    2: Timestamp timeRequested;
    3: Timestamp timeStartedRunning;
    4: StatusUpdate lastStatusUpdate
}

struct ExitedCommandStatus {
    1: Command command;
    2: Timestamp timeRequested;
    3: Timestamp timeStartedRunning;
    4: StatusUpdate lastStatusUpdate;
    5: Timestamp exitTime;
    6: bool wasCancelled;
}

struct StatusUpdate {
    1: string statusMessage;
    2: Timestamp timestamp;
    3: bool error;
    4: i32 exitCode
}

struct Timestamp {
    1: i64 timestamp
}

enum StrataNodeType {
    STANDALONE = 1,
    WORKER = 2,
    UNKNOWN = 3
}

struct GetConfigRequest {
    1: string clusterGuid;
    2: string workerToken;
    3: i32 lastKnownConfigGeneration;
    4: bool includeBlobInResponseIFFNewerVersion
}

struct GetConfigResult {
    1: string masterToken;
    2: i32 configGeneration;
    3: string configBlob;
    4: string error
}

service DaemonCommands {
    StrataNodeType getNodeType()
    GetConfigResult getConfig(1:GetConfigRequest request)
    CommandStatusWithHandle runCommand(1:CommandWithTimeout commandWithTimeout)
}