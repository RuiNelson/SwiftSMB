//
// Part of SwiftSMB
// Error-Status.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import SMB2

public extension SMB {
    enum SMBStatusSeverity: UInt32, Equatable, CaseIterable, CustomDebugStringConvertible, Sendable {
        case success = 0x0000_0000
        case info = 0x4000_0000
        case warning = 0x8000_0000
        case error = 0xC000_0000

        static let mask: UInt32 = 0xC000_0000
        
        public var debugDescription: String {
            switch self {
            case .success:
                "Success"
            case .info:
                "Info"
            case .warning:
                "Warning"
            case .error:
                "Error"
            }
        }
    }

    enum SMBStatus: UInt32, CaseIterable, CustomStringConvertible, CustomDebugStringConvertible, Sendable {
        case success = 0x0000_0000
        case shutdown = 0xFFFF_FFFF
        case pending = 0x0000_0103
        case smbBadFid = 0x0006_0001
        case noMoreFiles = 0x8000_0006
        case unsuccessful = 0xC000_0001
        case notImplemented = 0xC000_0002
        case invalidInfoClass = 0xC000_0003
        case infoLengthMismatch = 0xC000_0004
        case accessViolation = 0xC000_0005
        case inPageError = 0xC000_0006
        case pagefileQuota = 0xC000_0007
        case invalidHandle = 0xC000_0008
        case badInitialStack = 0xC000_0009
        case badInitialPc = 0xC000_000A
        case invalidCid = 0xC000_000B
        case timerNotCanceled = 0xC000_000C
        case invalidParameter = 0xC000_000D
        case noSuchDevice = 0xC000_000E
        case noSuchFile = 0xC000_000F
        case invalidDeviceRequest = 0xC000_0010
        case endOfFile = 0xC000_0011
        case wrongVolume = 0xC000_0012
        case noMediaInDevice = 0xC000_0013
        case unrecognizedMedia = 0xC000_0014
        case nonexistentSector = 0xC000_0015
        case moreProcessingRequired = 0xC000_0016
        case noMemory = 0xC000_0017
        case conflictingAddresses = 0xC000_0018
        case notMappedView = 0xC000_0019
        case unableToFreeVm = 0xC000_001A
        case unableToDeleteSection = 0xC000_001B
        case invalidSystemService = 0xC000_001C
        case illegalInstruction = 0xC000_001D
        case invalidLockSequence = 0xC000_001E
        case invalidViewSize = 0xC000_001F
        case invalidFileForSection = 0xC000_0020
        case alreadyCommitted = 0xC000_0021
        case accessDenied = 0xC000_0022
        case bufferTooSmall = 0xC000_0023
        case objectTypeMismatch = 0xC000_0024
        case noncontinuableException = 0xC000_0025
        case invalidDisposition = 0xC000_0026
        case unwind = 0xC000_0027
        case badStack = 0xC000_0028
        case invalidUnwindTarget = 0xC000_0029
        case notLocked = 0xC000_002A
        case parityError = 0xC000_002B
        case unableToDecommitVm = 0xC000_002C
        case notCommitted = 0xC000_002D
        case invalidPortAttributes = 0xC000_002E
        case portMessageTooLong = 0xC000_002F
        case invalidParameterMix = 0xC000_0030
        case invalidQuotaLower = 0xC000_0031
        case diskCorruptError = 0xC000_0032
        case objectNameInvalid = 0xC000_0033
        case objectNameNotFound = 0xC000_0034
        case objectNameCollision = 0xC000_0035
        case handleNotWaitable = 0xC000_0036
        case portDisconnected = 0xC000_0037
        case deviceAlreadyAttached = 0xC000_0038
        case objectPathInvalid = 0xC000_0039
        case objectPathNotFound = 0xC000_003A
        case objectPathSyntaxBad = 0xC000_003B
        case dataOverrun = 0xC000_003C
        case dataLateError = 0xC000_003D
        case dataError = 0xC000_003E
        case crcError = 0xC000_003F
        case sectionTooBig = 0xC000_0040
        case portConnectionRefused = 0xC000_0041
        case invalidPortHandle = 0xC000_0042
        case sharingViolation = 0xC000_0043
        case quotaExceeded = 0xC000_0044
        case invalidPageProtection = 0xC000_0045
        case mutantNotOwned = 0xC000_0046
        case semaphoreLimitExceeded = 0xC000_0047
        case portAlreadySet = 0xC000_0048
        case sectionNotImage = 0xC000_0049
        case suspendCountExceeded = 0xC000_004A
        case threadIsTerminating = 0xC000_004B
        case badWorkingSetLimit = 0xC000_004C
        case incompatibleFileMap = 0xC000_004D
        case sectionProtection = 0xC000_004E
        case easNotSupported = 0xC000_004F
        case eaTooLarge = 0xC000_0050
        case nonexistentEaEntry = 0xC000_0051
        case noEasOnFile = 0xC000_0052
        case eaCorruptError = 0xC000_0053
        case fileLockConflict = 0xC000_0054
        case lockNotGranted = 0xC000_0055
        case deletePending = 0xC000_0056
        case ctlFileNotSupported = 0xC000_0057
        case unknownRevision = 0xC000_0058
        case revisionMismatch = 0xC000_0059
        case invalidOwner = 0xC000_005A
        case invalidPrimaryGroup = 0xC000_005B
        case noImpersonationToken = 0xC000_005C
        case cantDisableMandatory = 0xC000_005D
        case noLogonServers = 0xC000_005E
        case noSuchLogonSession = 0xC000_005F
        case noSuchPrivilege = 0xC000_0060
        case privilegeNotHeld = 0xC000_0061
        case invalidAccountName = 0xC000_0062
        case userExists = 0xC000_0063
        case noSuchUser = 0xC000_0064
        case groupExists = 0xC000_0065
        case noSuchGroup = 0xC000_0066
        case memberInGroup = 0xC000_0067
        case memberNotInGroup = 0xC000_0068
        case lastAdmin = 0xC000_0069
        case wrongPassword = 0xC000_006A
        case illFormedPassword = 0xC000_006B
        case passwordRestriction = 0xC000_006C
        case logonFailure = 0xC000_006D
        case accountRestriction = 0xC000_006E
        case invalidLogonHours = 0xC000_006F
        case invalidWorkstation = 0xC000_0070
        case passwordExpired = 0xC000_0071
        case accountDisabled = 0xC000_0072
        case noneMapped = 0xC000_0073
        case tooManyLuidsRequested = 0xC000_0074
        case luidsExhausted = 0xC000_0075
        case invalidSubAuthority = 0xC000_0076
        case invalidAcl = 0xC000_0077
        case invalidSid = 0xC000_0078
        case invalidSecurityDescr = 0xC000_0079
        case procedureNotFound = 0xC000_007A
        case invalidImageFormat = 0xC000_007B
        case noToken = 0xC000_007C
        case badInheritanceAcl = 0xC000_007D
        case rangeNotLocked = 0xC000_007E
        case diskFull = 0xC000_007F
        case serverDisabled = 0xC000_0080
        case serverNotDisabled = 0xC000_0081
        case tooManyGuidsRequested = 0xC000_0082
        case guidsExhausted = 0xC000_0083
        case invalidIDAuthority = 0xC000_0084
        case agentsExhausted = 0xC000_0085
        case invalidVolumeLabel = 0xC000_0086
        case sectionNotExtended = 0xC000_0087
        case notMappedData = 0xC000_0088
        case resourceDataNotFound = 0xC000_0089
        case resourceTypeNotFound = 0xC000_008A
        case resourceNameNotFound = 0xC000_008B
        case arrayBoundsExceeded = 0xC000_008C
        case floatDenormalOperand = 0xC000_008D
        case floatDivideByZero = 0xC000_008E
        case floatInexactResult = 0xC000_008F
        case floatInvalidOperation = 0xC000_0090
        case floatOverflow = 0xC000_0091
        case floatStackCheck = 0xC000_0092
        case floatUnderflow = 0xC000_0093
        case integerDivideByZero = 0xC000_0094
        case integerOverflow = 0xC000_0095
        case privilegedInstruction = 0xC000_0096
        case tooManyPagingFiles = 0xC000_0097
        case fileInvalid = 0xC000_0098
        case allottedSpaceExceeded = 0xC000_0099
        case insufficientResources = 0xC000_009A
        case dfsExitPathFound = 0xC000_009B
        case deviceDataError = 0xC000_009C
        case deviceNotConnected = 0xC000_009D
        case devicePowerFailure = 0xC000_009E
        case freeVmNotAtBase = 0xC000_009F
        case memoryNotAllocated = 0xC000_00A0
        case workingSetQuota = 0xC000_00A1
        case mediaWriteProtected = 0xC000_00A2
        case deviceNotReady = 0xC000_00A3
        case invalidGroupAttributes = 0xC000_00A4
        case badImpersonationLevel = 0xC000_00A5
        case cantOpenAnonymous = 0xC000_00A6
        case badValidationClass = 0xC000_00A7
        case badTokenType = 0xC000_00A8
        case badMasterBootRecord = 0xC000_00A9
        case instructionMisalignment = 0xC000_00AA
        case instanceNotAvailable = 0xC000_00AB
        case pipeNotAvailable = 0xC000_00AC
        case invalidPipeState = 0xC000_00AD
        case pipeBusy = 0xC000_00AE
        case illegalFunction = 0xC000_00AF
        case pipeDisconnected = 0xC000_00B0
        case pipeClosing = 0xC000_00B1
        case pipeConnected = 0xC000_00B2
        case pipeListening = 0xC000_00B3
        case invalidReadMode = 0xC000_00B4
        case ioTimeout = 0xC000_00B5
        case fileForcedClosed = 0xC000_00B6
        case profilingNotStarted = 0xC000_00B7
        case profilingNotStopped = 0xC000_00B8
        case couldNotInterpret = 0xC000_00B9
        case fileIsADirectory = 0xC000_00BA
        case notSupported = 0xC000_00BB
        case remoteNotListening = 0xC000_00BC
        case duplicateName = 0xC000_00BD
        case badNetworkPath = 0xC000_00BE
        case networkBusy = 0xC000_00BF
        case deviceDoesNotExist = 0xC000_00C0
        case tooManyCommands = 0xC000_00C1
        case adapterHardwareError = 0xC000_00C2
        case invalidNetworkResponse = 0xC000_00C3
        case unexpectedNetworkError = 0xC000_00C4
        case badRemoteAdapter = 0xC000_00C5
        case printQueueFull = 0xC000_00C6
        case noSpoolSpace = 0xC000_00C7
        case printCancelled = 0xC000_00C8
        case networkNameDeleted = 0xC000_00C9
        case networkAccessDenied = 0xC000_00CA
        case badDeviceType = 0xC000_00CB
        case badNetworkName = 0xC000_00CC
        case tooManyNames = 0xC000_00CD
        case tooManySessions = 0xC000_00CE
        case sharingPaused = 0xC000_00CF
        case requestNotAccepted = 0xC000_00D0
        case redirectorPaused = 0xC000_00D1
        case netWriteFault = 0xC000_00D2
        case profilingAtLimit = 0xC000_00D3
        case notSameDevice = 0xC000_00D4
        case fileRenamed = 0xC000_00D5
        case virtualCircuitClosed = 0xC000_00D6
        case noSecurityOnObject = 0xC000_00D7
        case cantWait = 0xC000_00D8
        case pipeEmpty = 0xC000_00D9
        case cantAccessDomainInfo = 0xC000_00DA
        case cantTerminateSelf = 0xC000_00DB
        case invalidServerState = 0xC000_00DC
        case invalidDomainState = 0xC000_00DD
        case invalidDomainRole = 0xC000_00DE
        case noSuchDomain = 0xC000_00DF
        case domainExists = 0xC000_00E0
        case domainLimitExceeded = 0xC000_00E1
        case oplockNotGranted = 0xC000_00E2
        case invalidOplockProtocol = 0xC000_00E3
        case internalDbCorruption = 0xC000_00E4
        case internalError = 0xC000_00E5
        case genericNotMapped = 0xC000_00E6
        case badDescriptorFormat = 0xC000_00E7
        case invalidUserBuffer = 0xC000_00E8
        case unexpectedIoError = 0xC000_00E9
        case unexpectedMmCreateErr = 0xC000_00EA
        case unexpectedMmMapError = 0xC000_00EB
        case unexpectedMmExtendErr = 0xC000_00EC
        case notLogonProcess = 0xC000_00ED
        case logonSessionExists = 0xC000_00EE
        case invalidParameter1 = 0xC000_00EF
        case invalidParameter2 = 0xC000_00F0
        case invalidParameter3 = 0xC000_00F1
        case invalidParameter4 = 0xC000_00F2
        case invalidParameter5 = 0xC000_00F3
        case invalidParameter6 = 0xC000_00F4
        case invalidParameter7 = 0xC000_00F5
        case invalidParameter8 = 0xC000_00F6
        case invalidParameter9 = 0xC000_00F7
        case invalidParameter10 = 0xC000_00F8
        case invalidParameter11 = 0xC000_00F9
        case invalidParameter12 = 0xC000_00FA
        case redirectorNotStarted = 0xC000_00FB
        case redirectorStarted = 0xC000_00FC
        case stackOverflow = 0xC000_00FD
        case noSuchPackage = 0xC000_00FE
        case badFunctionTable = 0xC000_00FF
        case directoryNotEmpty = 0xC000_0101
        case fileCorruptError = 0xC000_0102
        case notADirectory = 0xC000_0103
        case badLogonSessionState = 0xC000_0104
        case logonSessionCollision = 0xC000_0105
        case nameTooLong = 0xC000_0106
        case filesOpen = 0xC000_0107
        case connectionInUse = 0xC000_0108
        case messageNotFound = 0xC000_0109
        case processIsTerminating = 0xC000_010A
        case invalidLogonType = 0xC000_010B
        case noGuidTranslation = 0xC000_010C
        case cannotImpersonate = 0xC000_010D
        case imageAlreadyLoaded = 0xC000_010E
        case abiosNotPresent = 0xC000_010F
        case abiosLidNotExist = 0xC000_0110
        case abiosLidAlreadyOwned = 0xC000_0111
        case abiosNotLidOwner = 0xC000_0112
        case abiosInvalidCommand = 0xC000_0113
        case abiosInvalidLid = 0xC000_0114
        case abiosSelectorNotAvailable = 0xC000_0115
        case abiosInvalidSelector = 0xC000_0116
        case noLdt = 0xC000_0117
        case invalidLdtSize = 0xC000_0118
        case invalidLdtOffset = 0xC000_0119
        case invalidLdtDescriptor = 0xC000_011A
        case invalidImageNeFormat = 0xC000_011B
        case rxactInvalidState = 0xC000_011C
        case rxactCommitFailure = 0xC000_011D
        case mappedFileSizeZero = 0xC000_011E
        case tooManyOpenedFiles = 0xC000_011F
        case cancelled = 0xC000_0120
        case cannotDelete = 0xC000_0121
        case invalidComputerName = 0xC000_0122
        case fileDeleted = 0xC000_0123
        case specialAccount = 0xC000_0124
        case specialGroup = 0xC000_0125
        case specialUser = 0xC000_0126
        case membersPrimaryGroup = 0xC000_0127
        case fileClosed = 0xC000_0128
        case tooManyThreads = 0xC000_0129
        case threadNotInProcess = 0xC000_012A
        case tokenAlreadyInUse = 0xC000_012B
        case pagefileQuotaExceeded = 0xC000_012C
        case commitmentLimit = 0xC000_012D
        case invalidImageLeFormat = 0xC000_012E
        case invalidImageNotMz = 0xC000_012F
        case invalidImageProtect = 0xC000_0130
        case invalidImageWin16 = 0xC000_0131
        case logonServerConflict = 0xC000_0132
        case timeDifferenceAtDc = 0xC000_0133
        case synchronizationRequired = 0xC000_0134
        case dllNotFound = 0xC000_0135
        case openFailed = 0xC000_0136
        case ioPrivilegeFailed = 0xC000_0137
        case ordinalNotFound = 0xC000_0138
        case entrypointNotFound = 0xC000_0139
        case controlCExit = 0xC000_013A
        case localDisconnect = 0xC000_013B
        case remoteDisconnect = 0xC000_013C
        case remoteResources = 0xC000_013D
        case linkFailed = 0xC000_013E
        case linkTimeout = 0xC000_013F
        case invalidConnection = 0xC000_0140
        case invalidAddress = 0xC000_0141
        case dllInitFailed = 0xC000_0142
        case missingSystemfile = 0xC000_0143
        case unhandledException = 0xC000_0144
        case appInitFailure = 0xC000_0145
        case pagefileCreateFailed = 0xC000_0146
        case noPagefile = 0xC000_0147
        case invalidLevel = 0xC000_0148
        case wrongPasswordCore = 0xC000_0149
        case illegalFloatContext = 0xC000_014A
        case pipeBroken = 0xC000_014B
        case registryCorrupt = 0xC000_014C
        case registryIoFailed = 0xC000_014D
        case noEventPair = 0xC000_014E
        case unrecognizedVolume = 0xC000_014F
        case serialNoDeviceInited = 0xC000_0150
        case noSuchAlias = 0xC000_0151
        case memberNotInAlias = 0xC000_0152
        case memberInAlias = 0xC000_0153
        case aliasExists = 0xC000_0154
        case logonNotGranted = 0xC000_0155
        case tooManySecrets = 0xC000_0156
        case secretTooLong = 0xC000_0157
        case internalDbError = 0xC000_0158
        case fullscreenMode = 0xC000_0159
        case tooManyContextIDs = 0xC000_015A
        case logonTypeNotGranted = 0xC000_015B
        case notRegistryFile = 0xC000_015C
        case ntCrossEncryptionRequired = 0xC000_015D
        case domainCtrlrConfigError = 0xC000_015E
        case ftMissingMember = 0xC000_015F
        case illFormedServiceEntry = 0xC000_0160
        case illegalCharacter = 0xC000_0161
        case unmappableCharacter = 0xC000_0162
        case undefinedCharacter = 0xC000_0163
        case floppyVolume = 0xC000_0164
        case floppyIDMarkNotFound = 0xC000_0165
        case floppyWrongCylinder = 0xC000_0166
        case floppyUnknownError = 0xC000_0167
        case floppyBadRegisters = 0xC000_0168
        case diskRecalibrateFailed = 0xC000_0169
        case diskOperationFailed = 0xC000_016A
        case diskResetFailed = 0xC000_016B
        case sharedIrqBusy = 0xC000_016C
        case ftOrphaning = 0xC000_016D
        case partitionFailure = 0xC000_0172
        case invalidBlockLength = 0xC000_0173
        case deviceNotPartitioned = 0xC000_0174
        case unableToLockMedia = 0xC000_0175
        case unableToUnloadMedia = 0xC000_0176
        case eomOverflow = 0xC000_0177
        case noMedia = 0xC000_0178
        case noSuchMember = 0xC000_017A
        case invalidMember = 0xC000_017B
        case keyDeleted = 0xC000_017C
        case noLogSpace = 0xC000_017D
        case tooManySids = 0xC000_017E
        case lmCrossEncryptionRequired = 0xC000_017F
        case keyHasChildren = 0xC000_0180
        case childMustBeVolatile = 0xC000_0181
        case deviceConfigurationError = 0xC000_0182
        case driverInternalError = 0xC000_0183
        case invalidDeviceState = 0xC000_0184
        case ioDeviceError = 0xC000_0185
        case deviceProtocolError = 0xC000_0186
        case backupController = 0xC000_0187
        case logFileFull = 0xC000_0188
        case tooLate = 0xC000_0189
        case noTrustLsaSecret = 0xC000_018A
        case noTrustSamAccount = 0xC000_018B
        case trustedDomainFailure = 0xC000_018C
        case trustedRelationshipFailure = 0xC000_018D
        case eventlogFileCorrupt = 0xC000_018E
        case eventlogCantStart = 0xC000_018F
        case trustFailure = 0xC000_0190
        case mutantLimitExceeded = 0xC000_0191
        case netlogonNotStarted = 0xC000_0192
        case accountExpired = 0xC000_0193
        case possibleDeadlock = 0xC000_0194
        case networkCredentialConflict = 0xC000_0195
        case remoteSessionLimit = 0xC000_0196
        case eventlogFileChanged = 0xC000_0197
        case nologonInterdomainTrustAccount = 0xC000_0198
        case nologonWorkstationTrustAccount = 0xC000_0199
        case nologonServerTrustAccount = 0xC000_019A
        case domainTrustInconsistent = 0xC000_019B
        case fsDriverRequired = 0xC000_019C
        case noUserSessionKey = 0xC000_0202
        case userSessionDeleted = 0xC000_0203
        case resourceLangNotFound = 0xC000_0204
        case insuffServerResources = 0xC000_0205
        case invalidBufferSize = 0xC000_0206
        case invalidAddressComponent = 0xC000_0207
        case invalidAddressWildcard = 0xC000_0208
        case tooManyAddresses = 0xC000_0209
        case addressAlreadyExists = 0xC000_020A
        case addressClosed = 0xC000_020B
        case connectionDisconnected = 0xC000_020C
        case connectionReset = 0xC000_020D
        case tooManyNodes = 0xC000_020E
        case transactionAborted = 0xC000_020F
        case transactionTimedOut = 0xC000_0210
        case transactionNoRelease = 0xC000_0211
        case transactionNoMatch = 0xC000_0212
        case transactionResponded = 0xC000_0213
        case transactionInvalidID = 0xC000_0214
        case transactionInvalidType = 0xC000_0215
        case notServerSession = 0xC000_0216
        case notClientSession = 0xC000_0217
        case cannotLoadRegistryFile = 0xC000_0218
        case debugAttachFailed = 0xC000_0219
        case systemProcessTerminated = 0xC000_021A
        case dataNotAccepted = 0xC000_021B
        case noBrowserServersFound = 0xC000_021C
        case vdmHardError = 0xC000_021D
        case driverCancelTimeout = 0xC000_021E
        case replyMessageMismatch = 0xC000_021F
        case mappedAlignment = 0xC000_0220
        case imageChecksumMismatch = 0xC000_0221
        case lostWritebehindData = 0xC000_0222
        case clientServerParametersInvalid = 0xC000_0223
        case passwordMustChange = 0xC000_0224
        case notFound = 0xC000_0225
        case notTinyStream = 0xC000_0226
        case recoveryFailure = 0xC000_0227
        case stackOverflowRead = 0xC000_0228
        case failCheck = 0xC000_0229
        case duplicateObjectid = 0xC000_022A
        case objectidExists = 0xC000_022B
        case convertToLarge = 0xC000_022C
        case retry = 0xC000_022D
        case foundOutOfScope = 0xC000_022E
        case allocateBucket = 0xC000_022F
        case propsetNotFound = 0xC000_0230
        case marshallOverflow = 0xC000_0231
        case invalidVariant = 0xC000_0232
        case domainControllerNotFound = 0xC000_0233
        case accountLockedOut = 0xC000_0234
        case handleNotClosable = 0xC000_0235
        case connectionRefused = 0xC000_0236
        case gracefulDisconnect = 0xC000_0237
        case addressAlreadyAssociated = 0xC000_0238
        case addressNotAssociated = 0xC000_0239
        case connectionInvalid = 0xC000_023A
        case connectionActive = 0xC000_023B
        case networkUnreachable = 0xC000_023C
        case hostUnreachable = 0xC000_023D
        case protocolUnreachable = 0xC000_023E
        case portUnreachable = 0xC000_023F
        case requestAborted = 0xC000_0240
        case connectionAborted = 0xC000_0241
        case badCompressionBuffer = 0xC000_0242
        case userMappedFile = 0xC000_0243
        case auditFailed = 0xC000_0244
        case timerResolutionNotSet = 0xC000_0245
        case connectionCountLimit = 0xC000_0246
        case loginTimeRestriction = 0xC000_0247
        case loginWkstaRestriction = 0xC000_0248
        case imageMpUpMismatch = 0xC000_0249
        case insufficientLogonInfo = 0xC000_0250
        case badDllEntrypoint = 0xC000_0251
        case badServiceEntrypoint = 0xC000_0252
        case lpcReplyLost = 0xC000_0253
        case ipAddressConflict1 = 0xC000_0254
        case ipAddressConflict2 = 0xC000_0255
        case registryQuotaLimit = 0xC000_0256
        case pathNotCovered = 0xC000_0257
        case noCallbackActive = 0xC000_0258
        case licenseQuotaExceeded = 0xC000_0259
        case pwdTooShort = 0xC000_025A
        case pwdTooRecent = 0xC000_025B
        case pwdHistoryConflict = 0xC000_025C
        case plugplayNoDevice = 0xC000_025E
        case unsupportedCompression = 0xC000_025F
        case invalidHwProfile = 0xC000_0260
        case invalidPlugplayDevicePath = 0xC000_0261
        case driverOrdinalNotFound = 0xC000_0262
        case driverEntrypointNotFound = 0xC000_0263
        case resourceNotOwned = 0xC000_0264
        case tooManyLinks = 0xC000_0265
        case quotaListInconsistent = 0xC000_0266
        case fileIsOffline = 0xC000_0267
        case volumeDismounted = 0xC000_026E
        case notAReparsePoint = 0xC000_0275
        case serverUnavailable = 0xC000_0466
        case bufferOverflow = 0x8000_0005
        case stoppedOnSymlink = 0x8000_002D

        public var name: String {
            switch self {
            case .success:
                "SMB2_STATUS_SUCCESS"
            case .shutdown:
                "SMB2_STATUS_SHUTDOWN"
            case .pending:
                "SMB2_STATUS_PENDING"
            case .smbBadFid:
                "SMB2_STATUS_SMB_BAD_FID"
            case .noMoreFiles:
                "SMB2_STATUS_NO_MORE_FILES"
            case .unsuccessful:
                "SMB2_STATUS_UNSUCCESSFUL"
            case .notImplemented:
                "SMB2_STATUS_NOT_IMPLEMENTED"
            case .invalidInfoClass:
                "SMB2_STATUS_INVALID_INFO_CLASS"
            case .infoLengthMismatch:
                "SMB2_STATUS_INFO_LENGTH_MISMATCH"
            case .accessViolation:
                "SMB2_STATUS_ACCESS_VIOLATION"
            case .inPageError:
                "SMB2_STATUS_IN_PAGE_ERROR"
            case .pagefileQuota:
                "SMB2_STATUS_PAGEFILE_QUOTA"
            case .invalidHandle:
                "SMB2_STATUS_INVALID_HANDLE"
            case .badInitialStack:
                "SMB2_STATUS_BAD_INITIAL_STACK"
            case .badInitialPc:
                "SMB2_STATUS_BAD_INITIAL_PC"
            case .invalidCid:
                "SMB2_STATUS_INVALID_CID"
            case .timerNotCanceled:
                "SMB2_STATUS_TIMER_NOT_CANCELED"
            case .invalidParameter:
                "SMB2_STATUS_INVALID_PARAMETER"
            case .noSuchDevice:
                "SMB2_STATUS_NO_SUCH_DEVICE"
            case .noSuchFile:
                "SMB2_STATUS_NO_SUCH_FILE"
            case .invalidDeviceRequest:
                "SMB2_STATUS_INVALID_DEVICE_REQUEST"
            case .endOfFile:
                "SMB2_STATUS_END_OF_FILE"
            case .wrongVolume:
                "SMB2_STATUS_WRONG_VOLUME"
            case .noMediaInDevice:
                "SMB2_STATUS_NO_MEDIA_IN_DEVICE"
            case .unrecognizedMedia:
                "SMB2_STATUS_UNRECOGNIZED_MEDIA"
            case .nonexistentSector:
                "SMB2_STATUS_NONEXISTENT_SECTOR"
            case .moreProcessingRequired:
                "SMB2_STATUS_MORE_PROCESSING_REQUIRED"
            case .noMemory:
                "SMB2_STATUS_NO_MEMORY"
            case .conflictingAddresses:
                "SMB2_STATUS_CONFLICTING_ADDRESSES"
            case .notMappedView:
                "SMB2_STATUS_NOT_MAPPED_VIEW"
            case .unableToFreeVm:
                "SMB2_STATUS_UNABLE_TO_FREE_VM"
            case .unableToDeleteSection:
                "SMB2_STATUS_UNABLE_TO_DELETE_SECTION"
            case .invalidSystemService:
                "SMB2_STATUS_INVALID_SYSTEM_SERVICE"
            case .illegalInstruction:
                "SMB2_STATUS_ILLEGAL_INSTRUCTION"
            case .invalidLockSequence:
                "SMB2_STATUS_INVALID_LOCK_SEQUENCE"
            case .invalidViewSize:
                "SMB2_STATUS_INVALID_VIEW_SIZE"
            case .invalidFileForSection:
                "SMB2_STATUS_INVALID_FILE_FOR_SECTION"
            case .alreadyCommitted:
                "SMB2_STATUS_ALREADY_COMMITTED"
            case .accessDenied:
                "SMB2_STATUS_ACCESS_DENIED"
            case .bufferTooSmall:
                "SMB2_STATUS_BUFFER_TOO_SMALL"
            case .objectTypeMismatch:
                "SMB2_STATUS_OBJECT_TYPE_MISMATCH"
            case .noncontinuableException:
                "SMB2_STATUS_NONCONTINUABLE_EXCEPTION"
            case .invalidDisposition:
                "SMB2_STATUS_INVALID_DISPOSITION"
            case .unwind:
                "SMB2_STATUS_UNWIND"
            case .badStack:
                "SMB2_STATUS_BAD_STACK"
            case .invalidUnwindTarget:
                "SMB2_STATUS_INVALID_UNWIND_TARGET"
            case .notLocked:
                "SMB2_STATUS_NOT_LOCKED"
            case .parityError:
                "SMB2_STATUS_PARITY_ERROR"
            case .unableToDecommitVm:
                "SMB2_STATUS_UNABLE_TO_DECOMMIT_VM"
            case .notCommitted:
                "SMB2_STATUS_NOT_COMMITTED"
            case .invalidPortAttributes:
                "SMB2_STATUS_INVALID_PORT_ATTRIBUTES"
            case .portMessageTooLong:
                "SMB2_STATUS_PORT_MESSAGE_TOO_LONG"
            case .invalidParameterMix:
                "SMB2_STATUS_INVALID_PARAMETER_MIX"
            case .invalidQuotaLower:
                "SMB2_STATUS_INVALID_QUOTA_LOWER"
            case .diskCorruptError:
                "SMB2_STATUS_DISK_CORRUPT_ERROR"
            case .objectNameInvalid:
                "SMB2_STATUS_OBJECT_NAME_INVALID"
            case .objectNameNotFound:
                "SMB2_STATUS_OBJECT_NAME_NOT_FOUND"
            case .objectNameCollision:
                "SMB2_STATUS_OBJECT_NAME_COLLISION"
            case .handleNotWaitable:
                "SMB2_STATUS_HANDLE_NOT_WAITABLE"
            case .portDisconnected:
                "SMB2_STATUS_PORT_DISCONNECTED"
            case .deviceAlreadyAttached:
                "SMB2_STATUS_DEVICE_ALREADY_ATTACHED"
            case .objectPathInvalid:
                "SMB2_STATUS_OBJECT_PATH_INVALID"
            case .objectPathNotFound:
                "SMB2_STATUS_OBJECT_PATH_NOT_FOUND"
            case .objectPathSyntaxBad:
                "SMB2_STATUS_OBJECT_PATH_SYNTAX_BAD"
            case .dataOverrun:
                "SMB2_STATUS_DATA_OVERRUN"
            case .dataLateError:
                "SMB2_STATUS_DATA_LATE_ERROR"
            case .dataError:
                "SMB2_STATUS_DATA_ERROR"
            case .crcError:
                "SMB2_STATUS_CRC_ERROR"
            case .sectionTooBig:
                "SMB2_STATUS_SECTION_TOO_BIG"
            case .portConnectionRefused:
                "SMB2_STATUS_PORT_CONNECTION_REFUSED"
            case .invalidPortHandle:
                "SMB2_STATUS_INVALID_PORT_HANDLE"
            case .sharingViolation:
                "SMB2_STATUS_SHARING_VIOLATION"
            case .quotaExceeded:
                "SMB2_STATUS_QUOTA_EXCEEDED"
            case .invalidPageProtection:
                "SMB2_STATUS_INVALID_PAGE_PROTECTION"
            case .mutantNotOwned:
                "SMB2_STATUS_MUTANT_NOT_OWNED"
            case .semaphoreLimitExceeded:
                "SMB2_STATUS_SEMAPHORE_LIMIT_EXCEEDED"
            case .portAlreadySet:
                "SMB2_STATUS_PORT_ALREADY_SET"
            case .sectionNotImage:
                "SMB2_STATUS_SECTION_NOT_IMAGE"
            case .suspendCountExceeded:
                "SMB2_STATUS_SUSPEND_COUNT_EXCEEDED"
            case .threadIsTerminating:
                "SMB2_STATUS_THREAD_IS_TERMINATING"
            case .badWorkingSetLimit:
                "SMB2_STATUS_BAD_WORKING_SET_LIMIT"
            case .incompatibleFileMap:
                "SMB2_STATUS_INCOMPATIBLE_FILE_MAP"
            case .sectionProtection:
                "SMB2_STATUS_SECTION_PROTECTION"
            case .easNotSupported:
                "SMB2_STATUS_EAS_NOT_SUPPORTED"
            case .eaTooLarge:
                "SMB2_STATUS_EA_TOO_LARGE"
            case .nonexistentEaEntry:
                "SMB2_STATUS_NONEXISTENT_EA_ENTRY"
            case .noEasOnFile:
                "SMB2_STATUS_NO_EAS_ON_FILE"
            case .eaCorruptError:
                "SMB2_STATUS_EA_CORRUPT_ERROR"
            case .fileLockConflict:
                "SMB2_STATUS_FILE_LOCK_CONFLICT"
            case .lockNotGranted:
                "SMB2_STATUS_LOCK_NOT_GRANTED"
            case .deletePending:
                "SMB2_STATUS_DELETE_PENDING"
            case .ctlFileNotSupported:
                "SMB2_STATUS_CTL_FILE_NOT_SUPPORTED"
            case .unknownRevision:
                "SMB2_STATUS_UNKNOWN_REVISION"
            case .revisionMismatch:
                "SMB2_STATUS_REVISION_MISMATCH"
            case .invalidOwner:
                "SMB2_STATUS_INVALID_OWNER"
            case .invalidPrimaryGroup:
                "SMB2_STATUS_INVALID_PRIMARY_GROUP"
            case .noImpersonationToken:
                "SMB2_STATUS_NO_IMPERSONATION_TOKEN"
            case .cantDisableMandatory:
                "SMB2_STATUS_CANT_DISABLE_MANDATORY"
            case .noLogonServers:
                "SMB2_STATUS_NO_LOGON_SERVERS"
            case .noSuchLogonSession:
                "SMB2_STATUS_NO_SUCH_LOGON_SESSION"
            case .noSuchPrivilege:
                "SMB2_STATUS_NO_SUCH_PRIVILEGE"
            case .privilegeNotHeld:
                "SMB2_STATUS_PRIVILEGE_NOT_HELD"
            case .invalidAccountName:
                "SMB2_STATUS_INVALID_ACCOUNT_NAME"
            case .userExists:
                "SMB2_STATUS_USER_EXISTS"
            case .noSuchUser:
                "SMB2_STATUS_NO_SUCH_USER"
            case .groupExists:
                "SMB2_STATUS_GROUP_EXISTS"
            case .noSuchGroup:
                "SMB2_STATUS_NO_SUCH_GROUP"
            case .memberInGroup:
                "SMB2_STATUS_MEMBER_IN_GROUP"
            case .memberNotInGroup:
                "SMB2_STATUS_MEMBER_NOT_IN_GROUP"
            case .lastAdmin:
                "SMB2_STATUS_LAST_ADMIN"
            case .wrongPassword:
                "SMB2_STATUS_WRONG_PASSWORD"
            case .illFormedPassword:
                "SMB2_STATUS_ILL_FORMED_PASSWORD"
            case .passwordRestriction:
                "SMB2_STATUS_PASSWORD_RESTRICTION"
            case .logonFailure:
                "SMB2_STATUS_LOGON_FAILURE"
            case .accountRestriction:
                "SMB2_STATUS_ACCOUNT_RESTRICTION"
            case .invalidLogonHours:
                "SMB2_STATUS_INVALID_LOGON_HOURS"
            case .invalidWorkstation:
                "SMB2_STATUS_INVALID_WORKSTATION"
            case .passwordExpired:
                "SMB2_STATUS_PASSWORD_EXPIRED"
            case .accountDisabled:
                "SMB2_STATUS_ACCOUNT_DISABLED"
            case .noneMapped:
                "SMB2_STATUS_NONE_MAPPED"
            case .tooManyLuidsRequested:
                "SMB2_STATUS_TOO_MANY_LUIDS_REQUESTED"
            case .luidsExhausted:
                "SMB2_STATUS_LUIDS_EXHAUSTED"
            case .invalidSubAuthority:
                "SMB2_STATUS_INVALID_SUB_AUTHORITY"
            case .invalidAcl:
                "SMB2_STATUS_INVALID_ACL"
            case .invalidSid:
                "SMB2_STATUS_INVALID_SID"
            case .invalidSecurityDescr:
                "SMB2_STATUS_INVALID_SECURITY_DESCR"
            case .procedureNotFound:
                "SMB2_STATUS_PROCEDURE_NOT_FOUND"
            case .invalidImageFormat:
                "SMB2_STATUS_INVALID_IMAGE_FORMAT"
            case .noToken:
                "SMB2_STATUS_NO_TOKEN"
            case .badInheritanceAcl:
                "SMB2_STATUS_BAD_INHERITANCE_ACL"
            case .rangeNotLocked:
                "SMB2_STATUS_RANGE_NOT_LOCKED"
            case .diskFull:
                "SMB2_STATUS_DISK_FULL"
            case .serverDisabled:
                "SMB2_STATUS_SERVER_DISABLED"
            case .serverNotDisabled:
                "SMB2_STATUS_SERVER_NOT_DISABLED"
            case .tooManyGuidsRequested:
                "SMB2_STATUS_TOO_MANY_GUIDS_REQUESTED"
            case .guidsExhausted:
                "SMB2_STATUS_GUIDS_EXHAUSTED"
            case .invalidIDAuthority:
                "SMB2_STATUS_INVALID_ID_AUTHORITY"
            case .agentsExhausted:
                "SMB2_STATUS_AGENTS_EXHAUSTED"
            case .invalidVolumeLabel:
                "SMB2_STATUS_INVALID_VOLUME_LABEL"
            case .sectionNotExtended:
                "SMB2_STATUS_SECTION_NOT_EXTENDED"
            case .notMappedData:
                "SMB2_STATUS_NOT_MAPPED_DATA"
            case .resourceDataNotFound:
                "SMB2_STATUS_RESOURCE_DATA_NOT_FOUND"
            case .resourceTypeNotFound:
                "SMB2_STATUS_RESOURCE_TYPE_NOT_FOUND"
            case .resourceNameNotFound:
                "SMB2_STATUS_RESOURCE_NAME_NOT_FOUND"
            case .arrayBoundsExceeded:
                "SMB2_STATUS_ARRAY_BOUNDS_EXCEEDED"
            case .floatDenormalOperand:
                "SMB2_STATUS_FLOAT_DENORMAL_OPERAND"
            case .floatDivideByZero:
                "SMB2_STATUS_FLOAT_DIVIDE_BY_ZERO"
            case .floatInexactResult:
                "SMB2_STATUS_FLOAT_INEXACT_RESULT"
            case .floatInvalidOperation:
                "SMB2_STATUS_FLOAT_INVALID_OPERATION"
            case .floatOverflow:
                "SMB2_STATUS_FLOAT_OVERFLOW"
            case .floatStackCheck:
                "SMB2_STATUS_FLOAT_STACK_CHECK"
            case .floatUnderflow:
                "SMB2_STATUS_FLOAT_UNDERFLOW"
            case .integerDivideByZero:
                "SMB2_STATUS_INTEGER_DIVIDE_BY_ZERO"
            case .integerOverflow:
                "SMB2_STATUS_INTEGER_OVERFLOW"
            case .privilegedInstruction:
                "SMB2_STATUS_PRIVILEGED_INSTRUCTION"
            case .tooManyPagingFiles:
                "SMB2_STATUS_TOO_MANY_PAGING_FILES"
            case .fileInvalid:
                "SMB2_STATUS_FILE_INVALID"
            case .allottedSpaceExceeded:
                "SMB2_STATUS_ALLOTTED_SPACE_EXCEEDED"
            case .insufficientResources:
                "SMB2_STATUS_INSUFFICIENT_RESOURCES"
            case .dfsExitPathFound:
                "SMB2_STATUS_DFS_EXIT_PATH_FOUND"
            case .deviceDataError:
                "SMB2_STATUS_DEVICE_DATA_ERROR"
            case .deviceNotConnected:
                "SMB2_STATUS_DEVICE_NOT_CONNECTED"
            case .devicePowerFailure:
                "SMB2_STATUS_DEVICE_POWER_FAILURE"
            case .freeVmNotAtBase:
                "SMB2_STATUS_FREE_VM_NOT_AT_BASE"
            case .memoryNotAllocated:
                "SMB2_STATUS_MEMORY_NOT_ALLOCATED"
            case .workingSetQuota:
                "SMB2_STATUS_WORKING_SET_QUOTA"
            case .mediaWriteProtected:
                "SMB2_STATUS_MEDIA_WRITE_PROTECTED"
            case .deviceNotReady:
                "SMB2_STATUS_DEVICE_NOT_READY"
            case .invalidGroupAttributes:
                "SMB2_STATUS_INVALID_GROUP_ATTRIBUTES"
            case .badImpersonationLevel:
                "SMB2_STATUS_BAD_IMPERSONATION_LEVEL"
            case .cantOpenAnonymous:
                "SMB2_STATUS_CANT_OPEN_ANONYMOUS"
            case .badValidationClass:
                "SMB2_STATUS_BAD_VALIDATION_CLASS"
            case .badTokenType:
                "SMB2_STATUS_BAD_TOKEN_TYPE"
            case .badMasterBootRecord:
                "SMB2_STATUS_BAD_MASTER_BOOT_RECORD"
            case .instructionMisalignment:
                "SMB2_STATUS_INSTRUCTION_MISALIGNMENT"
            case .instanceNotAvailable:
                "SMB2_STATUS_INSTANCE_NOT_AVAILABLE"
            case .pipeNotAvailable:
                "SMB2_STATUS_PIPE_NOT_AVAILABLE"
            case .invalidPipeState:
                "SMB2_STATUS_INVALID_PIPE_STATE"
            case .pipeBusy:
                "SMB2_STATUS_PIPE_BUSY"
            case .illegalFunction:
                "SMB2_STATUS_ILLEGAL_FUNCTION"
            case .pipeDisconnected:
                "SMB2_STATUS_PIPE_DISCONNECTED"
            case .pipeClosing:
                "SMB2_STATUS_PIPE_CLOSING"
            case .pipeConnected:
                "SMB2_STATUS_PIPE_CONNECTED"
            case .pipeListening:
                "SMB2_STATUS_PIPE_LISTENING"
            case .invalidReadMode:
                "SMB2_STATUS_INVALID_READ_MODE"
            case .ioTimeout:
                "SMB2_STATUS_IO_TIMEOUT"
            case .fileForcedClosed:
                "SMB2_STATUS_FILE_FORCED_CLOSED"
            case .profilingNotStarted:
                "SMB2_STATUS_PROFILING_NOT_STARTED"
            case .profilingNotStopped:
                "SMB2_STATUS_PROFILING_NOT_STOPPED"
            case .couldNotInterpret:
                "SMB2_STATUS_COULD_NOT_INTERPRET"
            case .fileIsADirectory:
                "SMB2_STATUS_FILE_IS_A_DIRECTORY"
            case .notSupported:
                "SMB2_STATUS_NOT_SUPPORTED"
            case .remoteNotListening:
                "SMB2_STATUS_REMOTE_NOT_LISTENING"
            case .duplicateName:
                "SMB2_STATUS_DUPLICATE_NAME"
            case .badNetworkPath:
                "SMB2_STATUS_BAD_NETWORK_PATH"
            case .networkBusy:
                "SMB2_STATUS_NETWORK_BUSY"
            case .deviceDoesNotExist:
                "SMB2_STATUS_DEVICE_DOES_NOT_EXIST"
            case .tooManyCommands:
                "SMB2_STATUS_TOO_MANY_COMMANDS"
            case .adapterHardwareError:
                "SMB2_STATUS_ADAPTER_HARDWARE_ERROR"
            case .invalidNetworkResponse:
                "SMB2_STATUS_INVALID_NETWORK_RESPONSE"
            case .unexpectedNetworkError:
                "SMB2_STATUS_UNEXPECTED_NETWORK_ERROR"
            case .badRemoteAdapter:
                "SMB2_STATUS_BAD_REMOTE_ADAPTER"
            case .printQueueFull:
                "SMB2_STATUS_PRINT_QUEUE_FULL"
            case .noSpoolSpace:
                "SMB2_STATUS_NO_SPOOL_SPACE"
            case .printCancelled:
                "SMB2_STATUS_PRINT_CANCELLED"
            case .networkNameDeleted:
                "SMB2_STATUS_NETWORK_NAME_DELETED"
            case .networkAccessDenied:
                "SMB2_STATUS_NETWORK_ACCESS_DENIED"
            case .badDeviceType:
                "SMB2_STATUS_BAD_DEVICE_TYPE"
            case .badNetworkName:
                "SMB2_STATUS_BAD_NETWORK_NAME"
            case .tooManyNames:
                "SMB2_STATUS_TOO_MANY_NAMES"
            case .tooManySessions:
                "SMB2_STATUS_TOO_MANY_SESSIONS"
            case .sharingPaused:
                "SMB2_STATUS_SHARING_PAUSED"
            case .requestNotAccepted:
                "SMB2_STATUS_REQUEST_NOT_ACCEPTED"
            case .redirectorPaused:
                "SMB2_STATUS_REDIRECTOR_PAUSED"
            case .netWriteFault:
                "SMB2_STATUS_NET_WRITE_FAULT"
            case .profilingAtLimit:
                "SMB2_STATUS_PROFILING_AT_LIMIT"
            case .notSameDevice:
                "SMB2_STATUS_NOT_SAME_DEVICE"
            case .fileRenamed:
                "SMB2_STATUS_FILE_RENAMED"
            case .virtualCircuitClosed:
                "SMB2_STATUS_VIRTUAL_CIRCUIT_CLOSED"
            case .noSecurityOnObject:
                "SMB2_STATUS_NO_SECURITY_ON_OBJECT"
            case .cantWait:
                "SMB2_STATUS_CANT_WAIT"
            case .pipeEmpty:
                "SMB2_STATUS_PIPE_EMPTY"
            case .cantAccessDomainInfo:
                "SMB2_STATUS_CANT_ACCESS_DOMAIN_INFO"
            case .cantTerminateSelf:
                "SMB2_STATUS_CANT_TERMINATE_SELF"
            case .invalidServerState:
                "SMB2_STATUS_INVALID_SERVER_STATE"
            case .invalidDomainState:
                "SMB2_STATUS_INVALID_DOMAIN_STATE"
            case .invalidDomainRole:
                "SMB2_STATUS_INVALID_DOMAIN_ROLE"
            case .noSuchDomain:
                "SMB2_STATUS_NO_SUCH_DOMAIN"
            case .domainExists:
                "SMB2_STATUS_DOMAIN_EXISTS"
            case .domainLimitExceeded:
                "SMB2_STATUS_DOMAIN_LIMIT_EXCEEDED"
            case .oplockNotGranted:
                "SMB2_STATUS_OPLOCK_NOT_GRANTED"
            case .invalidOplockProtocol:
                "SMB2_STATUS_INVALID_OPLOCK_PROTOCOL"
            case .internalDbCorruption:
                "SMB2_STATUS_INTERNAL_DB_CORRUPTION"
            case .internalError:
                "SMB2_STATUS_INTERNAL_ERROR"
            case .genericNotMapped:
                "SMB2_STATUS_GENERIC_NOT_MAPPED"
            case .badDescriptorFormat:
                "SMB2_STATUS_BAD_DESCRIPTOR_FORMAT"
            case .invalidUserBuffer:
                "SMB2_STATUS_INVALID_USER_BUFFER"
            case .unexpectedIoError:
                "SMB2_STATUS_UNEXPECTED_IO_ERROR"
            case .unexpectedMmCreateErr:
                "SMB2_STATUS_UNEXPECTED_MM_CREATE_ERR"
            case .unexpectedMmMapError:
                "SMB2_STATUS_UNEXPECTED_MM_MAP_ERROR"
            case .unexpectedMmExtendErr:
                "SMB2_STATUS_UNEXPECTED_MM_EXTEND_ERR"
            case .notLogonProcess:
                "SMB2_STATUS_NOT_LOGON_PROCESS"
            case .logonSessionExists:
                "SMB2_STATUS_LOGON_SESSION_EXISTS"
            case .invalidParameter1:
                "SMB2_STATUS_INVALID_PARAMETER_1"
            case .invalidParameter2:
                "SMB2_STATUS_INVALID_PARAMETER_2"
            case .invalidParameter3:
                "SMB2_STATUS_INVALID_PARAMETER_3"
            case .invalidParameter4:
                "SMB2_STATUS_INVALID_PARAMETER_4"
            case .invalidParameter5:
                "SMB2_STATUS_INVALID_PARAMETER_5"
            case .invalidParameter6:
                "SMB2_STATUS_INVALID_PARAMETER_6"
            case .invalidParameter7:
                "SMB2_STATUS_INVALID_PARAMETER_7"
            case .invalidParameter8:
                "SMB2_STATUS_INVALID_PARAMETER_8"
            case .invalidParameter9:
                "SMB2_STATUS_INVALID_PARAMETER_9"
            case .invalidParameter10:
                "SMB2_STATUS_INVALID_PARAMETER_10"
            case .invalidParameter11:
                "SMB2_STATUS_INVALID_PARAMETER_11"
            case .invalidParameter12:
                "SMB2_STATUS_INVALID_PARAMETER_12"
            case .redirectorNotStarted:
                "SMB2_STATUS_REDIRECTOR_NOT_STARTED"
            case .redirectorStarted:
                "SMB2_STATUS_REDIRECTOR_STARTED"
            case .stackOverflow:
                "SMB2_STATUS_STACK_OVERFLOW"
            case .noSuchPackage:
                "SMB2_STATUS_NO_SUCH_PACKAGE"
            case .badFunctionTable:
                "SMB2_STATUS_BAD_FUNCTION_TABLE"
            case .directoryNotEmpty:
                "SMB2_STATUS_DIRECTORY_NOT_EMPTY"
            case .fileCorruptError:
                "SMB2_STATUS_FILE_CORRUPT_ERROR"
            case .notADirectory:
                "SMB2_STATUS_NOT_A_DIRECTORY"
            case .badLogonSessionState:
                "SMB2_STATUS_BAD_LOGON_SESSION_STATE"
            case .logonSessionCollision:
                "SMB2_STATUS_LOGON_SESSION_COLLISION"
            case .nameTooLong:
                "SMB2_STATUS_NAME_TOO_LONG"
            case .filesOpen:
                "SMB2_STATUS_FILES_OPEN"
            case .connectionInUse:
                "SMB2_STATUS_CONNECTION_IN_USE"
            case .messageNotFound:
                "SMB2_STATUS_MESSAGE_NOT_FOUND"
            case .processIsTerminating:
                "SMB2_STATUS_PROCESS_IS_TERMINATING"
            case .invalidLogonType:
                "SMB2_STATUS_INVALID_LOGON_TYPE"
            case .noGuidTranslation:
                "SMB2_STATUS_NO_GUID_TRANSLATION"
            case .cannotImpersonate:
                "SMB2_STATUS_CANNOT_IMPERSONATE"
            case .imageAlreadyLoaded:
                "SMB2_STATUS_IMAGE_ALREADY_LOADED"
            case .abiosNotPresent:
                "SMB2_STATUS_ABIOS_NOT_PRESENT"
            case .abiosLidNotExist:
                "SMB2_STATUS_ABIOS_LID_NOT_EXIST"
            case .abiosLidAlreadyOwned:
                "SMB2_STATUS_ABIOS_LID_ALREADY_OWNED"
            case .abiosNotLidOwner:
                "SMB2_STATUS_ABIOS_NOT_LID_OWNER"
            case .abiosInvalidCommand:
                "SMB2_STATUS_ABIOS_INVALID_COMMAND"
            case .abiosInvalidLid:
                "SMB2_STATUS_ABIOS_INVALID_LID"
            case .abiosSelectorNotAvailable:
                "SMB2_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE"
            case .abiosInvalidSelector:
                "SMB2_STATUS_ABIOS_INVALID_SELECTOR"
            case .noLdt:
                "SMB2_STATUS_NO_LDT"
            case .invalidLdtSize:
                "SMB2_STATUS_INVALID_LDT_SIZE"
            case .invalidLdtOffset:
                "SMB2_STATUS_INVALID_LDT_OFFSET"
            case .invalidLdtDescriptor:
                "SMB2_STATUS_INVALID_LDT_DESCRIPTOR"
            case .invalidImageNeFormat:
                "SMB2_STATUS_INVALID_IMAGE_NE_FORMAT"
            case .rxactInvalidState:
                "SMB2_STATUS_RXACT_INVALID_STATE"
            case .rxactCommitFailure:
                "SMB2_STATUS_RXACT_COMMIT_FAILURE"
            case .mappedFileSizeZero:
                "SMB2_STATUS_MAPPED_FILE_SIZE_ZERO"
            case .tooManyOpenedFiles:
                "SMB2_STATUS_TOO_MANY_OPENED_FILES"
            case .cancelled:
                "SMB2_STATUS_CANCELLED"
            case .cannotDelete:
                "SMB2_STATUS_CANNOT_DELETE"
            case .invalidComputerName:
                "SMB2_STATUS_INVALID_COMPUTER_NAME"
            case .fileDeleted:
                "SMB2_STATUS_FILE_DELETED"
            case .specialAccount:
                "SMB2_STATUS_SPECIAL_ACCOUNT"
            case .specialGroup:
                "SMB2_STATUS_SPECIAL_GROUP"
            case .specialUser:
                "SMB2_STATUS_SPECIAL_USER"
            case .membersPrimaryGroup:
                "SMB2_STATUS_MEMBERS_PRIMARY_GROUP"
            case .fileClosed:
                "SMB2_STATUS_FILE_CLOSED"
            case .tooManyThreads:
                "SMB2_STATUS_TOO_MANY_THREADS"
            case .threadNotInProcess:
                "SMB2_STATUS_THREAD_NOT_IN_PROCESS"
            case .tokenAlreadyInUse:
                "SMB2_STATUS_TOKEN_ALREADY_IN_USE"
            case .pagefileQuotaExceeded:
                "SMB2_STATUS_PAGEFILE_QUOTA_EXCEEDED"
            case .commitmentLimit:
                "SMB2_STATUS_COMMITMENT_LIMIT"
            case .invalidImageLeFormat:
                "SMB2_STATUS_INVALID_IMAGE_LE_FORMAT"
            case .invalidImageNotMz:
                "SMB2_STATUS_INVALID_IMAGE_NOT_MZ"
            case .invalidImageProtect:
                "SMB2_STATUS_INVALID_IMAGE_PROTECT"
            case .invalidImageWin16:
                "SMB2_STATUS_INVALID_IMAGE_WIN_16"
            case .logonServerConflict:
                "SMB2_STATUS_LOGON_SERVER_CONFLICT"
            case .timeDifferenceAtDc:
                "SMB2_STATUS_TIME_DIFFERENCE_AT_DC"
            case .synchronizationRequired:
                "SMB2_STATUS_SYNCHRONIZATION_REQUIRED"
            case .dllNotFound:
                "SMB2_STATUS_DLL_NOT_FOUND"
            case .openFailed:
                "SMB2_STATUS_OPEN_FAILED"
            case .ioPrivilegeFailed:
                "SMB2_STATUS_IO_PRIVILEGE_FAILED"
            case .ordinalNotFound:
                "SMB2_STATUS_ORDINAL_NOT_FOUND"
            case .entrypointNotFound:
                "SMB2_STATUS_ENTRYPOINT_NOT_FOUND"
            case .controlCExit:
                "SMB2_STATUS_CONTROL_C_EXIT"
            case .localDisconnect:
                "SMB2_STATUS_LOCAL_DISCONNECT"
            case .remoteDisconnect:
                "SMB2_STATUS_REMOTE_DISCONNECT"
            case .remoteResources:
                "SMB2_STATUS_REMOTE_RESOURCES"
            case .linkFailed:
                "SMB2_STATUS_LINK_FAILED"
            case .linkTimeout:
                "SMB2_STATUS_LINK_TIMEOUT"
            case .invalidConnection:
                "SMB2_STATUS_INVALID_CONNECTION"
            case .invalidAddress:
                "SMB2_STATUS_INVALID_ADDRESS"
            case .dllInitFailed:
                "SMB2_STATUS_DLL_INIT_FAILED"
            case .missingSystemfile:
                "SMB2_STATUS_MISSING_SYSTEMFILE"
            case .unhandledException:
                "SMB2_STATUS_UNHANDLED_EXCEPTION"
            case .appInitFailure:
                "SMB2_STATUS_APP_INIT_FAILURE"
            case .pagefileCreateFailed:
                "SMB2_STATUS_PAGEFILE_CREATE_FAILED"
            case .noPagefile:
                "SMB2_STATUS_NO_PAGEFILE"
            case .invalidLevel:
                "SMB2_STATUS_INVALID_LEVEL"
            case .wrongPasswordCore:
                "SMB2_STATUS_WRONG_PASSWORD_CORE"
            case .illegalFloatContext:
                "SMB2_STATUS_ILLEGAL_FLOAT_CONTEXT"
            case .pipeBroken:
                "SMB2_STATUS_PIPE_BROKEN"
            case .registryCorrupt:
                "SMB2_STATUS_REGISTRY_CORRUPT"
            case .registryIoFailed:
                "SMB2_STATUS_REGISTRY_IO_FAILED"
            case .noEventPair:
                "SMB2_STATUS_NO_EVENT_PAIR"
            case .unrecognizedVolume:
                "SMB2_STATUS_UNRECOGNIZED_VOLUME"
            case .serialNoDeviceInited:
                "SMB2_STATUS_SERIAL_NO_DEVICE_INITED"
            case .noSuchAlias:
                "SMB2_STATUS_NO_SUCH_ALIAS"
            case .memberNotInAlias:
                "SMB2_STATUS_MEMBER_NOT_IN_ALIAS"
            case .memberInAlias:
                "SMB2_STATUS_MEMBER_IN_ALIAS"
            case .aliasExists:
                "SMB2_STATUS_ALIAS_EXISTS"
            case .logonNotGranted:
                "SMB2_STATUS_LOGON_NOT_GRANTED"
            case .tooManySecrets:
                "SMB2_STATUS_TOO_MANY_SECRETS"
            case .secretTooLong:
                "SMB2_STATUS_SECRET_TOO_LONG"
            case .internalDbError:
                "SMB2_STATUS_INTERNAL_DB_ERROR"
            case .fullscreenMode:
                "SMB2_STATUS_FULLSCREEN_MODE"
            case .tooManyContextIDs:
                "SMB2_STATUS_TOO_MANY_CONTEXT_IDS"
            case .logonTypeNotGranted:
                "SMB2_STATUS_LOGON_TYPE_NOT_GRANTED"
            case .notRegistryFile:
                "SMB2_STATUS_NOT_REGISTRY_FILE"
            case .ntCrossEncryptionRequired:
                "SMB2_STATUS_NT_CROSS_ENCRYPTION_REQUIRED"
            case .domainCtrlrConfigError:
                "SMB2_STATUS_DOMAIN_CTRLR_CONFIG_ERROR"
            case .ftMissingMember:
                "SMB2_STATUS_FT_MISSING_MEMBER"
            case .illFormedServiceEntry:
                "SMB2_STATUS_ILL_FORMED_SERVICE_ENTRY"
            case .illegalCharacter:
                "SMB2_STATUS_ILLEGAL_CHARACTER"
            case .unmappableCharacter:
                "SMB2_STATUS_UNMAPPABLE_CHARACTER"
            case .undefinedCharacter:
                "SMB2_STATUS_UNDEFINED_CHARACTER"
            case .floppyVolume:
                "SMB2_STATUS_FLOPPY_VOLUME"
            case .floppyIDMarkNotFound:
                "SMB2_STATUS_FLOPPY_ID_MARK_NOT_FOUND"
            case .floppyWrongCylinder:
                "SMB2_STATUS_FLOPPY_WRONG_CYLINDER"
            case .floppyUnknownError:
                "SMB2_STATUS_FLOPPY_UNKNOWN_ERROR"
            case .floppyBadRegisters:
                "SMB2_STATUS_FLOPPY_BAD_REGISTERS"
            case .diskRecalibrateFailed:
                "SMB2_STATUS_DISK_RECALIBRATE_FAILED"
            case .diskOperationFailed:
                "SMB2_STATUS_DISK_OPERATION_FAILED"
            case .diskResetFailed:
                "SMB2_STATUS_DISK_RESET_FAILED"
            case .sharedIrqBusy:
                "SMB2_STATUS_SHARED_IRQ_BUSY"
            case .ftOrphaning:
                "SMB2_STATUS_FT_ORPHANING"
            case .partitionFailure:
                "SMB2_STATUS_PARTITION_FAILURE"
            case .invalidBlockLength:
                "SMB2_STATUS_INVALID_BLOCK_LENGTH"
            case .deviceNotPartitioned:
                "SMB2_STATUS_DEVICE_NOT_PARTITIONED"
            case .unableToLockMedia:
                "SMB2_STATUS_UNABLE_TO_LOCK_MEDIA"
            case .unableToUnloadMedia:
                "SMB2_STATUS_UNABLE_TO_UNLOAD_MEDIA"
            case .eomOverflow:
                "SMB2_STATUS_EOM_OVERFLOW"
            case .noMedia:
                "SMB2_STATUS_NO_MEDIA"
            case .noSuchMember:
                "SMB2_STATUS_NO_SUCH_MEMBER"
            case .invalidMember:
                "SMB2_STATUS_INVALID_MEMBER"
            case .keyDeleted:
                "SMB2_STATUS_KEY_DELETED"
            case .noLogSpace:
                "SMB2_STATUS_NO_LOG_SPACE"
            case .tooManySids:
                "SMB2_STATUS_TOO_MANY_SIDS"
            case .lmCrossEncryptionRequired:
                "SMB2_STATUS_LM_CROSS_ENCRYPTION_REQUIRED"
            case .keyHasChildren:
                "SMB2_STATUS_KEY_HAS_CHILDREN"
            case .childMustBeVolatile:
                "SMB2_STATUS_CHILD_MUST_BE_VOLATILE"
            case .deviceConfigurationError:
                "SMB2_STATUS_DEVICE_CONFIGURATION_ERROR"
            case .driverInternalError:
                "SMB2_STATUS_DRIVER_INTERNAL_ERROR"
            case .invalidDeviceState:
                "SMB2_STATUS_INVALID_DEVICE_STATE"
            case .ioDeviceError:
                "SMB2_STATUS_IO_DEVICE_ERROR"
            case .deviceProtocolError:
                "SMB2_STATUS_DEVICE_PROTOCOL_ERROR"
            case .backupController:
                "SMB2_STATUS_BACKUP_CONTROLLER"
            case .logFileFull:
                "SMB2_STATUS_LOG_FILE_FULL"
            case .tooLate:
                "SMB2_STATUS_TOO_LATE"
            case .noTrustLsaSecret:
                "SMB2_STATUS_NO_TRUST_LSA_SECRET"
            case .noTrustSamAccount:
                "SMB2_STATUS_NO_TRUST_SAM_ACCOUNT"
            case .trustedDomainFailure:
                "SMB2_STATUS_TRUSTED_DOMAIN_FAILURE"
            case .trustedRelationshipFailure:
                "SMB2_STATUS_TRUSTED_RELATIONSHIP_FAILURE"
            case .eventlogFileCorrupt:
                "SMB2_STATUS_EVENTLOG_FILE_CORRUPT"
            case .eventlogCantStart:
                "SMB2_STATUS_EVENTLOG_CANT_START"
            case .trustFailure:
                "SMB2_STATUS_TRUST_FAILURE"
            case .mutantLimitExceeded:
                "SMB2_STATUS_MUTANT_LIMIT_EXCEEDED"
            case .netlogonNotStarted:
                "SMB2_STATUS_NETLOGON_NOT_STARTED"
            case .accountExpired:
                "SMB2_STATUS_ACCOUNT_EXPIRED"
            case .possibleDeadlock:
                "SMB2_STATUS_POSSIBLE_DEADLOCK"
            case .networkCredentialConflict:
                "SMB2_STATUS_NETWORK_CREDENTIAL_CONFLICT"
            case .remoteSessionLimit:
                "SMB2_STATUS_REMOTE_SESSION_LIMIT"
            case .eventlogFileChanged:
                "SMB2_STATUS_EVENTLOG_FILE_CHANGED"
            case .nologonInterdomainTrustAccount:
                "SMB2_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT"
            case .nologonWorkstationTrustAccount:
                "SMB2_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT"
            case .nologonServerTrustAccount:
                "SMB2_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT"
            case .domainTrustInconsistent:
                "SMB2_STATUS_DOMAIN_TRUST_INCONSISTENT"
            case .fsDriverRequired:
                "SMB2_STATUS_FS_DRIVER_REQUIRED"
            case .noUserSessionKey:
                "SMB2_STATUS_NO_USER_SESSION_KEY"
            case .userSessionDeleted:
                "SMB2_STATUS_USER_SESSION_DELETED"
            case .resourceLangNotFound:
                "SMB2_STATUS_RESOURCE_LANG_NOT_FOUND"
            case .insuffServerResources:
                "SMB2_STATUS_INSUFF_SERVER_RESOURCES"
            case .invalidBufferSize:
                "SMB2_STATUS_INVALID_BUFFER_SIZE"
            case .invalidAddressComponent:
                "SMB2_STATUS_INVALID_ADDRESS_COMPONENT"
            case .invalidAddressWildcard:
                "SMB2_STATUS_INVALID_ADDRESS_WILDCARD"
            case .tooManyAddresses:
                "SMB2_STATUS_TOO_MANY_ADDRESSES"
            case .addressAlreadyExists:
                "SMB2_STATUS_ADDRESS_ALREADY_EXISTS"
            case .addressClosed:
                "SMB2_STATUS_ADDRESS_CLOSED"
            case .connectionDisconnected:
                "SMB2_STATUS_CONNECTION_DISCONNECTED"
            case .connectionReset:
                "SMB2_STATUS_CONNECTION_RESET"
            case .tooManyNodes:
                "SMB2_STATUS_TOO_MANY_NODES"
            case .transactionAborted:
                "SMB2_STATUS_TRANSACTION_ABORTED"
            case .transactionTimedOut:
                "SMB2_STATUS_TRANSACTION_TIMED_OUT"
            case .transactionNoRelease:
                "SMB2_STATUS_TRANSACTION_NO_RELEASE"
            case .transactionNoMatch:
                "SMB2_STATUS_TRANSACTION_NO_MATCH"
            case .transactionResponded:
                "SMB2_STATUS_TRANSACTION_RESPONDED"
            case .transactionInvalidID:
                "SMB2_STATUS_TRANSACTION_INVALID_ID"
            case .transactionInvalidType:
                "SMB2_STATUS_TRANSACTION_INVALID_TYPE"
            case .notServerSession:
                "SMB2_STATUS_NOT_SERVER_SESSION"
            case .notClientSession:
                "SMB2_STATUS_NOT_CLIENT_SESSION"
            case .cannotLoadRegistryFile:
                "SMB2_STATUS_CANNOT_LOAD_REGISTRY_FILE"
            case .debugAttachFailed:
                "SMB2_STATUS_DEBUG_ATTACH_FAILED"
            case .systemProcessTerminated:
                "SMB2_STATUS_SYSTEM_PROCESS_TERMINATED"
            case .dataNotAccepted:
                "SMB2_STATUS_DATA_NOT_ACCEPTED"
            case .noBrowserServersFound:
                "SMB2_STATUS_NO_BROWSER_SERVERS_FOUND"
            case .vdmHardError:
                "SMB2_STATUS_VDM_HARD_ERROR"
            case .driverCancelTimeout:
                "SMB2_STATUS_DRIVER_CANCEL_TIMEOUT"
            case .replyMessageMismatch:
                "SMB2_STATUS_REPLY_MESSAGE_MISMATCH"
            case .mappedAlignment:
                "SMB2_STATUS_MAPPED_ALIGNMENT"
            case .imageChecksumMismatch:
                "SMB2_STATUS_IMAGE_CHECKSUM_MISMATCH"
            case .lostWritebehindData:
                "SMB2_STATUS_LOST_WRITEBEHIND_DATA"
            case .clientServerParametersInvalid:
                "SMB2_STATUS_CLIENT_SERVER_PARAMETERS_INVALID"
            case .passwordMustChange:
                "SMB2_STATUS_PASSWORD_MUST_CHANGE"
            case .notFound:
                "SMB2_STATUS_NOT_FOUND"
            case .notTinyStream:
                "SMB2_STATUS_NOT_TINY_STREAM"
            case .recoveryFailure:
                "SMB2_STATUS_RECOVERY_FAILURE"
            case .stackOverflowRead:
                "SMB2_STATUS_STACK_OVERFLOW_READ"
            case .failCheck:
                "SMB2_STATUS_FAIL_CHECK"
            case .duplicateObjectid:
                "SMB2_STATUS_DUPLICATE_OBJECTID"
            case .objectidExists:
                "SMB2_STATUS_OBJECTID_EXISTS"
            case .convertToLarge:
                "SMB2_STATUS_CONVERT_TO_LARGE"
            case .retry:
                "SMB2_STATUS_RETRY"
            case .foundOutOfScope:
                "SMB2_STATUS_FOUND_OUT_OF_SCOPE"
            case .allocateBucket:
                "SMB2_STATUS_ALLOCATE_BUCKET"
            case .propsetNotFound:
                "SMB2_STATUS_PROPSET_NOT_FOUND"
            case .marshallOverflow:
                "SMB2_STATUS_MARSHALL_OVERFLOW"
            case .invalidVariant:
                "SMB2_STATUS_INVALID_VARIANT"
            case .domainControllerNotFound:
                "SMB2_STATUS_DOMAIN_CONTROLLER_NOT_FOUND"
            case .accountLockedOut:
                "SMB2_STATUS_ACCOUNT_LOCKED_OUT"
            case .handleNotClosable:
                "SMB2_STATUS_HANDLE_NOT_CLOSABLE"
            case .connectionRefused:
                "SMB2_STATUS_CONNECTION_REFUSED"
            case .gracefulDisconnect:
                "SMB2_STATUS_GRACEFUL_DISCONNECT"
            case .addressAlreadyAssociated:
                "SMB2_STATUS_ADDRESS_ALREADY_ASSOCIATED"
            case .addressNotAssociated:
                "SMB2_STATUS_ADDRESS_NOT_ASSOCIATED"
            case .connectionInvalid:
                "SMB2_STATUS_CONNECTION_INVALID"
            case .connectionActive:
                "SMB2_STATUS_CONNECTION_ACTIVE"
            case .networkUnreachable:
                "SMB2_STATUS_NETWORK_UNREACHABLE"
            case .hostUnreachable:
                "SMB2_STATUS_HOST_UNREACHABLE"
            case .protocolUnreachable:
                "SMB2_STATUS_PROTOCOL_UNREACHABLE"
            case .portUnreachable:
                "SMB2_STATUS_PORT_UNREACHABLE"
            case .requestAborted:
                "SMB2_STATUS_REQUEST_ABORTED"
            case .connectionAborted:
                "SMB2_STATUS_CONNECTION_ABORTED"
            case .badCompressionBuffer:
                "SMB2_STATUS_BAD_COMPRESSION_BUFFER"
            case .userMappedFile:
                "SMB2_STATUS_USER_MAPPED_FILE"
            case .auditFailed:
                "SMB2_STATUS_AUDIT_FAILED"
            case .timerResolutionNotSet:
                "SMB2_STATUS_TIMER_RESOLUTION_NOT_SET"
            case .connectionCountLimit:
                "SMB2_STATUS_CONNECTION_COUNT_LIMIT"
            case .loginTimeRestriction:
                "SMB2_STATUS_LOGIN_TIME_RESTRICTION"
            case .loginWkstaRestriction:
                "SMB2_STATUS_LOGIN_WKSTA_RESTRICTION"
            case .imageMpUpMismatch:
                "SMB2_STATUS_IMAGE_MP_UP_MISMATCH"
            case .insufficientLogonInfo:
                "SMB2_STATUS_INSUFFICIENT_LOGON_INFO"
            case .badDllEntrypoint:
                "SMB2_STATUS_BAD_DLL_ENTRYPOINT"
            case .badServiceEntrypoint:
                "SMB2_STATUS_BAD_SERVICE_ENTRYPOINT"
            case .lpcReplyLost:
                "SMB2_STATUS_LPC_REPLY_LOST"
            case .ipAddressConflict1:
                "SMB2_STATUS_IP_ADDRESS_CONFLICT1"
            case .ipAddressConflict2:
                "SMB2_STATUS_IP_ADDRESS_CONFLICT2"
            case .registryQuotaLimit:
                "SMB2_STATUS_REGISTRY_QUOTA_LIMIT"
            case .pathNotCovered:
                "SMB2_STATUS_PATH_NOT_COVERED"
            case .noCallbackActive:
                "SMB2_STATUS_NO_CALLBACK_ACTIVE"
            case .licenseQuotaExceeded:
                "SMB2_STATUS_LICENSE_QUOTA_EXCEEDED"
            case .pwdTooShort:
                "SMB2_STATUS_PWD_TOO_SHORT"
            case .pwdTooRecent:
                "SMB2_STATUS_PWD_TOO_RECENT"
            case .pwdHistoryConflict:
                "SMB2_STATUS_PWD_HISTORY_CONFLICT"
            case .plugplayNoDevice:
                "SMB2_STATUS_PLUGPLAY_NO_DEVICE"
            case .unsupportedCompression:
                "SMB2_STATUS_UNSUPPORTED_COMPRESSION"
            case .invalidHwProfile:
                "SMB2_STATUS_INVALID_HW_PROFILE"
            case .invalidPlugplayDevicePath:
                "SMB2_STATUS_INVALID_PLUGPLAY_DEVICE_PATH"
            case .driverOrdinalNotFound:
                "SMB2_STATUS_DRIVER_ORDINAL_NOT_FOUND"
            case .driverEntrypointNotFound:
                "SMB2_STATUS_DRIVER_ENTRYPOINT_NOT_FOUND"
            case .resourceNotOwned:
                "SMB2_STATUS_RESOURCE_NOT_OWNED"
            case .tooManyLinks:
                "SMB2_STATUS_TOO_MANY_LINKS"
            case .quotaListInconsistent:
                "SMB2_STATUS_QUOTA_LIST_INCONSISTENT"
            case .fileIsOffline:
                "SMB2_STATUS_FILE_IS_OFFLINE"
            case .volumeDismounted:
                "SMB2_STATUS_VOLUME_DISMOUNTED"
            case .notAReparsePoint:
                "SMB2_STATUS_NOT_A_REPARSE_POINT"
            case .serverUnavailable:
                "SMB2_STATUS_SERVER_UNAVAILABLE"
            case .bufferOverflow:
                "SMB2_STATUS_BUFFER_OVERFLOW"
            case .stoppedOnSymlink:
                "SMB2_STATUS_STOPPED_ON_SYMLINK"
            }
        }
        
        public var friendlyName: String {
            let lc = name
                .replacingOccurrences(of: "SMB2_STATUS_", with: "")
                .replacingOccurrences(of: "_", with: " ")
                .lowercased()
            
            return lc.prefix(1).uppercased() + lc.dropFirst()
        }
        
        public var description: String {
            debugDescription
        }

        public var severity: SMBStatusSeverity {
            SMBStatusSeverity(rawValue: rawValue & SMBStatusSeverity.mask)!
        }

        public var debugDescription: String {
            [
                name,
                "(\(hex(rawValue)))",
                "\t",
                "Severity:",
                severity.debugDescription,
            ]
                .joined(separator: " ")
        }
    }
}
