using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.IO;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Input;
using HpsBrowser.Commands;
using HpsBrowser.Models;
using HpsBrowser.Services;
using HpsBrowser.Views;
using Avalonia.Controls;
using Avalonia.Collections;
using Avalonia.Media.Imaging;
using Avalonia.Threading;

namespace HpsBrowser.ViewModels;

public sealed partial class MainViewModel : ViewModelBase
{
    private sealed record MonetaryTransferInfo(
        string TransferId,
        string TransferType,
        string Sender,
        string Receiver,
        int Amount,
        int FeeAmount,
        string FeeSource,
        string ContractId,
        List<string> LockedVoucherIds,
        string InterServerRaw
    );

    private sealed record PendingMinerSelection(
        string ClientNonce,
        List<string> Miners,
        string MinerListHash,
        string ServerCommit
    );

    private sealed record TourStep(string Title, string Body);
    private sealed record PublishContentResult(bool Success, string Hash, string Error);
    private sealed record PendingCriticalContractCertification(string TargetType, string TargetId, string ContractContentB64);
    private sealed record PendingOutgoingMessage(string TargetUser, string FileName, string MessageFileB64, string ActionType, bool UsesLocalBundleCredit, bool UsesImcServerCredit);
    private sealed record ContentResponseValidationResult(
        bool Success,
        byte[] Data,
        bool SignatureValid,
        string BrowserMessage,
        string CriticalCode,
        string CriticalTitle,
        string CriticalDetail,
        string Reason);

    private sealed record VoucherAuditEntry(string RawJson);
    private sealed record ExchangeTraceEntry(string RawJson);
    private readonly BrowserDatabase _database;
    private readonly CryptoService _cryptoService;
    private readonly IFileDialogService _fileDialogService;
    private readonly IPromptService _promptService;
    private readonly IContractDialogService _contractDialogService;
    private readonly SocketClientService _socketClient;
    private readonly ServerApiClient _serverApiClient;
    private readonly ContentService _contentService;
    private readonly bool _useUiDispatcher;
    private readonly bool _isMinerMode;
    private readonly Action<Action> _dispatch;
    private readonly string _nodeType;
    private readonly string _cryptoDir;
    private readonly string _dbPath;
    private RSA? _privateKey;
    private Window? _owner;
    private readonly Dictionary<string, string> _serverPublicKeys = new();
    private string? _clientAuthChallenge;
    private TaskCompletionSource<bool>? _authenticationResultTcs;
    private string _loginStatus = string.Empty;
    private string? _lastPowActionType;
    private string _status = "Desconectado";
    private string _user = "Não logado";
    private string _reputation = "100";
    private string _banStatus = string.Empty;
    private string _diskUsage = "0MB/500MB";
    private string _serverPriceSettingsText = string.Empty;
    private string _serverPriceSettingsStatus = string.Empty;
    private bool _canManageServerPrices;
    private string _serverPriceOwnerLabel = string.Empty;
    private string _messageTargetUser = string.Empty;
    private string _messageComposeText = string.Empty;
    private string _messageStatus = string.Empty;
    private string _messageStatusTitle = "Mensagens";
    private string _messageStatusForeground = "#EAEAEA";
    private string _messageStatusBackground = "#2A2418";
    private string _messageStatusBorderBrush = "#6E5730";
    private string _messageConversationText = string.Empty;
    private string _messageBundleStatus = string.Empty;
    private string _imcHpsStatus = string.Empty;
    private string _imcHpsSummary = "IMC-HPS foi removido desta versão.";
    private string _imcHpsExplainer = "A moeda auxiliar IMC-HPS fazia parte do fluxo de mensagens inter-servidor e foi removida.";
    private string _imcHpsServerLabel = string.Empty;
    private int _imcHpsServerBalanceValue;
    private int _messageLocalBundleRemaining;
    private int _messageLocalBundleSize = 10;
    private int _messageRemoteBundleRemaining;
    private int _messageRemoteBundleSize = 5;
    private string _messageComposeHelp = "Use @hash para anexos e #usuario ou #servidor@usuario para menções.";
    private DateTimeOffset _messageStatusPinnedUntil = DateTimeOffset.MinValue;
    private int _messageOperationVersion;
    private string _messageOperationKind = string.Empty;
    private string _lastOutgoingMessageRaw = string.Empty;
    private string _lastOutgoingMessageTarget = string.Empty;
    private PendingOutgoingMessage? _pendingOutgoingMessage;
    private string? _selectedMessageTargetOption;
    private MessageContactInfo? _selectedMessageContact;
    private MessageRequestInfo? _selectedIncomingMessageRequest;
    private readonly ObservableCollection<MessageContactInfo> _messageContacts = new();
    private readonly ObservableCollection<MessageRequestInfo> _incomingMessageRequests = new();
    private readonly ObservableCollection<MessageRequestInfo> _outgoingMessageRequests = new();
    private readonly ObservableCollection<string> _messageTargetOptions = new();
    private readonly ObservableCollection<string> _messageComposeSuggestions = new();
    private string _clientId = string.Empty;
    private string _sessionId = string.Empty;
    private string _nodeId = string.Empty;
    private string _publicKeyPem = string.Empty;
    private int _powThreads;
    private int _maxPowThreads;
    private string _powStatus = string.Empty;
    private string _powActionType = string.Empty;
    private int _powTargetBits;
    private string _powAttempts = "0";
    private string _powElapsed = "0s";
    private string _powHashrate = "0";
    private SearchWindow? _searchWindow;
    private ImportantFlowWindow? _importantFlowWindow;
    private string _importantFlowTitle = "Processo em andamento";
    private string _importantFlowStatus = string.Empty;
    private string _importantFlowDetails = string.Empty;
    private string _importantFlowLog = string.Empty;
    private string _importantFlowKind = string.Empty;
    private bool _importantFlowBusy;
    private bool _importantFlowCompletedVisible;
    private bool _isImportantFlowCompleted;
    private string _importantFlowCompletedText = "CONCLUÍDO";
    private DispatcherTimer? _importantFlowCompletedTimer;
    private DispatcherTimer? _importantFlowStageBlinkTimer;
    private ObservableCollection<FlowStageItem> _importantFlowStages = new();
    private int _importantFlowActiveStageIndex;
    private bool _isPowActive;
    private TourWindow? _tourWindow;
    private readonly List<TourStep> _tourSteps = new();
    private int _tourIndex;
    private string _tourTitle = string.Empty;
    private string _tourBody = string.Empty;
    private string _tourStepLabel = string.Empty;
    private bool _showTourOnStartup = true;

    private string _serverAddress = "localhost:8080";
    private string _username = string.Empty;
    private string _keyPassphrase = string.Empty;
    private string _localPublicKeyPem = string.Empty;
    private string _activeKeyUsername = string.Empty;
    private bool _autoLogin;
    private bool _saveKeys = true;
    private bool _useSsl;
    private bool _autoReconnect = true;
    private string _dnsDomain = string.Empty;
    private string _dnsContentHash = string.Empty;
    private string _dnsStatus = string.Empty;
    private string _browserUrl = "hps://rede";
    private string _browserContent = string.Empty;
    private Bitmap? _browserImage;
    private bool _isBrowserImageVisible;
    private bool _isBrowserTextVisible = true;
    private bool _isCriticalBrowserErrorVisible;
    private bool _canResolveCriticalBrowserError;
    private string _criticalBrowserErrorCode = string.Empty;
    private string _criticalBrowserErrorTitle = string.Empty;
    private string _criticalBrowserErrorMessage = string.Empty;
    private string _criticalBrowserTargetType = string.Empty;
    private string _criticalBrowserTargetId = string.Empty;
    private string _criticalBrowserReason = string.Empty;
    private int _clientPropagationSyncScheduled;
    private string _lastContentHash = string.Empty;
    private string _lastContentPublicKey = string.Empty;
    private bool _lastContentSignatureValid;
    private readonly List<string> _history = new();
    private int _historyIndex = -1;
    private byte[]? _lastContentBytes;
    private string _lastContentTitle = string.Empty;
    private string _lastContentMime = string.Empty;
    private ContentSecurityInfo? _lastContentInfo;
    private DomainSecurityInfo? _lastDomainInfo;
    private PendingDnsRegistration? _pendingDns;
    private string _hpsMintReason = "mining";
    private string _hpsMintStatus = string.Empty;
    private string _uploadFilePath = string.Empty;
    private string _uploadTitle = string.Empty;
    private string _uploadDescription = string.Empty;
    private string _uploadMimeType = string.Empty;
    private string _uploadStatus = string.Empty;
    private string _uploadHash = string.Empty;
    private PendingUpload? _pendingUpload;
    private PendingCriticalContractCertification? _pendingCriticalContractCertification;
    private TaskCompletionSource<PublishContentResult>? _contentPublishResultTcs;
    private const long MaxUploadSize = 100 * 1024 * 1024;
    private const int MaxInlineTextBytes = 1024 * 1024;
    private const int MaxTextProbeBytes = 256 * 1024;
    private static readonly TimeSpan ContentPublishAckTimeout = TimeSpan.FromSeconds(90);
    private ObservableCollection<Voucher> _vouchers = new();
    private ObservableCollection<DkvhpsLineageInfo> _dkvhpsLineages = new();
    private ObservableCollection<DkvhpsVoucherInfo> _dkvhpsLineageVouchers = new();
    private DkvhpsLineageInfo? _selectedDkvhpsLineage;
    private DkvhpsVoucherInfo? _selectedDkvhpsVoucher;
    private string _dkvhpsStatus = string.Empty;
    private string _dkvhpsLineageDetails = string.Empty;
    private string _dkvhpsVoucherDetails = string.Empty;
    private string _dkvhpsLineageCatalog = string.Empty;
    private string _hpsBalance = "0 HPS";
    private string _exchangeStatus = string.Empty;
    private string _exchangeQuoteMessage = string.Empty;
    private string _hpsWalletAlert = string.Empty;
    private string? _pendingExchangeQuoteId;
    private bool _exchangeConfirmPromptOpen;
    private string _voucherAuditInput = string.Empty;
    private string _voucherAuditSummary = string.Empty;
    private string _voucherAuditDetails = string.Empty;
    private string _spendAuditInput = string.Empty;
    private string _spendAuditSummary = string.Empty;
    private string _spendAuditDetails = string.Empty;
    private string? _pendingVoucherAuditRequestId;
    private string? _pendingSpendAuditRequestId;
    private ObservableCollection<ExchangeIssuerSummary> _exchangeIssuers = new();
    private ExchangeIssuerSummary? _selectedExchangeIssuer;
    private ObservableCollection<ExchangeServerStats> _exchangeServers = new();
    private ObservableCollection<ContractInfo> _contracts = new();
    private readonly List<ContractInfo> _contractFetchedResults = new();
    private readonly List<ContractInfo> _contractFilteredResults = new();
    private ContractInfo? _selectedContract;
    private string _contractFilter = "all";
    private string _contractSearchValue = string.Empty;
    private string _contractDetailsText = string.Empty;
    private int _contractCurrentPage = 1;
    private int _contractTotalCount;
    private int _contractServerTotalCount;
    private bool _contractLoadingPage;
    private string _contractLastServerSearchType = "all";
    private string _contractLastServerSearchValue = string.Empty;
    private const int ContractChunkSize = 10;
    private string _pendingTransferStatus = string.Empty;
    private int _pendingTransfersCount;
    private string? _pendingTransferId;
    private string? _pendingTransferType;
    private string? _pendingTransferAction;
    private readonly ConcurrentDictionary<string, PendingTransferInfo> _pendingTransfersByContract = new(StringComparer.OrdinalIgnoreCase);
    private readonly ObservableCollection<PendingTransferInfo> _pendingTransfers = new();
    private PendingTransferInfo? _selectedPendingTransfer;
    private readonly HashSet<string> _contractViolations = new();
    private readonly HashSet<string> _completedTransferIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _voucherConfirmationsInFlight = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _voucherConfirmationsCompleted = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _voucherConfirmationLock = new();
    private string _contractAlertText = string.Empty;
    private bool _contractAlertVisible;
    private DispatcherTimer? _contractAlertTimer;
    private bool _contractAlertBlinkOn;
    private string _transferStatus = string.Empty;
    private string? _pendingTransferUploadId;
    private readonly ObservableCollection<InventoryItem> _remotePublishedInventory = new();
    private readonly ObservableCollection<InventoryItem> _remoteLocalInventory = new();
    private readonly ObservableCollection<InventoryItem> _myInventoryItems = new();
    private readonly ObservableCollection<InventoryTransferRequest> _inventoryRequests = new();
    private DataGridCollectionView? _networkNodesView;

    private string _powLogText = string.Empty;
    private string _powSolvedCount = "0";
    private string _powTotalTime = "0s";
    private int _powSolvedTotal;
    private double _powTotalSeconds;
    private string _hpsMiningStatus = "Parado";
    private string _hpsMiningBits = "0";
    private string _hpsMiningElapsed = "0.0s";
    private string _hpsMiningHashrate = "0 H/s";
    private string _hpsMiningAttempts = "0";
    private string _hpsMiningCount = "0";
    private string _hpsMiningTotalTime = "0s";
    private readonly ConcurrentDictionary<string, MonetaryTransferInfo> _pendingMinerTransfers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _submittedMinerTransferAt = new(StringComparer.OrdinalIgnoreCase);
    private int _contractSearchRequestVersion;
    private readonly HashSet<string> _pendingInvalidationTransfers = new();
    private readonly Dictionary<string, string> _transferStatusCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _transferMinerCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, TaskCompletionSource<List<VoucherAuditEntry>>> _voucherAuditWaiters = new();
    private readonly Dictionary<string, TaskCompletionSource<List<ExchangeTraceEntry>>> _exchangeTraceWaiters = new();
    private string _minerPendingSignatures = "0";
    private string _minerFineStatus = string.Empty;
    private string _minerWithheldCount = "0";
    private string _minerWithheldValue = "0";
    private int _minerWithheldCountValue;
    private double _minerWithheldValueTotal;
    private int _minerPendingFines;
    private int _minerPendingDelayFines;
    private int _minerSignatureFines;
    private int _minerFineAmount;
    private int _minerFinePerPending;
    private bool _minerAutoPayFine;
    private bool _minerFinePromise;
    private bool _autoSignTransfers;
    private bool _autoAcceptMinerSelection;
    private bool _minerFineRequestInFlight;
    private string _minerFineRequestSource = string.Empty;
    private List<string> _pendingMinerFineVoucherIds = new();
    private bool _isContinuousMiningEnabled;
    private bool _isContinuousMiningInFlight;
    private readonly SemaphoreSlim _walletSyncSemaphore = new(1, 1);
    private string? _queuedWalletSyncPayloadJson;
    private int _walletSyncRunning;
    private int _automaticWalletRefreshPending;
    private int _automaticPendingTransfersRefreshPending;
    private int _automaticMinerPendingTransfersRefreshPending;
    private int _automaticStateRefreshWorkerRunning;
    private string _searchQuery = string.Empty;
    private string _searchContentType = "all";
    private string _searchSortBy = "reputation";
    private string _searchStatus = string.Empty;
    private ObservableCollection<SearchResult> _searchResults = new();
    private SearchResult? _selectedSearchResult;

    private bool _isLoggedIn;
    private int _selectedMainTabIndex;

    private string _selectedHpsAction = string.Empty;
    private string _hpsTargetUser = string.Empty;
    private string _hpsAppName = string.Empty;
    private string _hpsDomain = string.Empty;
    private string _hpsNewOwner = string.Empty;
    private string _hpsContentHash = string.Empty;
    private string _hpsTransferAmount = string.Empty;
    private string _hpsActionStatus = string.Empty;
    private readonly Dictionary<string, int> _hpsPowSkipCosts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _hpsPowSkipLabels = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<string>> _pendingHpsPayments = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _pendingHpsPaymentsAwaitingWalletSync = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _locallyBlockedSpendVoucherIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ApiAppRequest> _pendingApiAppRequests = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _apiAppBypassHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PendingMinerSelection> _pendingMinerSelections = new(StringComparer.OrdinalIgnoreCase);
    private bool _isHpsActionFile;
    private bool _isHpsActionHps;
    private bool _isHpsActionDomain;
    private bool _isHpsActionApiTransfer;
    private bool _isHpsActionApiCreate;

    private string _networkStats = "Nós: 0 | Conteúdo: 0 | DNS: 0";
    private string _networkStatus = string.Empty;
    private string _networkNodeSearch = string.Empty;
    private bool _hasNetworkNodesSnapshot;
    private NetworkNodeInfo? _selectedNetworkNode;
    private string _inventoryStatus = string.Empty;
    private bool _inventoryPublic = true;
    private InventoryItem? _selectedRemoteInventoryItem;
    private InventoryItem? _selectedMyInventoryItem;
    private InventoryTransferRequest? _selectedInventoryRequest;

    private string _newServerAddress = string.Empty;
    private ServerInfo? _selectedServer;
    private DnsRecord? _selectedDnsRecord;

    private PendingUsageContract? _pendingUsageContract;
    private PendingHpsTransfer? _pendingHpsTransfer;
    private string? _pendingHpsMintVoucherId;
    private string? _pendingExchangeTransferId;
    private string? _pendingExchangeVoucherId;
    private readonly HashSet<string> _pendingExchangeSourceVoucherIds = new(StringComparer.OrdinalIgnoreCase);
    private PendingInventoryTransfer? _pendingInventoryTransfer;
    private string? _pendingInventoryRequestId;
    private CancellationTokenSource? _powCts;
    private CancellationTokenSource? _pendingWalletRefreshCts;
    private CancellationTokenSource? _exchangePendingRefreshCts;
    private CancellationTokenSource? _powChallengeTimeoutCts;
    private int _reconnectInFlight;
    private int _intentionalDisconnectInFlight;
    private string _lastExchangePendingRefreshSnapshot = string.Empty;
    private DateTimeOffset _lastExchangePendingRefreshAt = DateTimeOffset.MinValue;
    private PowMonitorWindow? _powMonitorWindow;
    private int _powMonitorCloseVersion;
    private DispatcherTimer? _sessionTimer;
    private DateTimeOffset _sessionStartedAt = DateTimeOffset.UtcNow;
    private long _sessionBytesSent;
    private long _sessionBytesReceived;
    private int _contentDownloadedCount;
    private int _contentPublishedCount;
    private int _dnsRegisteredCount;
    private string _sessionElapsed = "0s";
    private string _dataSent = "0 B";
    private string _dataReceived = "0 B";
    private string _contentDownloadedLabel = "0 arquivos";
    private string _contentPublishedLabel = "0 arquivos";
    private string _dnsRegisteredLabel = "0 domínios";
    private readonly HashSet<string> _downloadedContentHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _publishedContentHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _knownPublishedContentHashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _dnsRegisteredDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _snapshotPersistenceLock = new();
    private readonly ObservableCollection<PhpsDebtInfo> _phpsMarketItems = new();
    private readonly ObservableCollection<PhpsDebtInfo> _myPhpsDebts = new();
    private PhpsDebtInfo? _selectedPhpsDebt;
    private string _phpsMarketStatus = string.Empty;
    private string _issuerRecheckStatus = string.Empty;
    private string _custodyDebtSummary = string.Empty;
    private int _snapshotPersistPending;
    private int _snapshotPersistWorkerRunning;
    private int _shutdownSealed;
    private readonly Mutex _databaseSnapshotMutex;
    private readonly bool _ownsDatabaseSnapshotMutex;
    private static readonly TimeSpan MinerSignatureResubmitCooldown = TimeSpan.FromSeconds(90);
    private bool _databaseInitialized;
    private int _signTransferInFlight;
    private int _pendingSignatureWorkerRunning;
    private string? _deferredAutoSignTransferId;
    private readonly Dictionary<string, FlowPopupViewModel> _flowPopups = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, FlowPopupWindow> _flowPopupWindows = new(StringComparer.OrdinalIgnoreCase);

    public MainViewModel(IFileDialogService? fileDialogService = null, IPromptService? promptService = null, IContractDialogService? contractDialogService = null, string? cryptoDirOverride = null, bool useUiDispatcher = true, bool minerMode = false)
    {
        _useUiDispatcher = useUiDispatcher;
        _isMinerMode = minerMode;
        _dispatch = useUiDispatcher
            ? action => Dispatcher.UIThread.Post(action)
            : action => action();
        _nodeType = minerMode ? "miner" : "client";
        _cryptoDir = string.IsNullOrWhiteSpace(cryptoDirOverride)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".hps_browser")
            : cryptoDirOverride;
        _dbPath = Path.Combine(_cryptoDir, "hps_browser.db");
        _database = new BrowserDatabase(_dbPath);
        _databaseSnapshotMutex = new Mutex(false, BuildDatabaseSnapshotMutexName(_dbPath));
        try
        {
            _ownsDatabaseSnapshotMutex = _databaseSnapshotMutex.WaitOne(0);
        }
        catch
        {
            _ownsDatabaseSnapshotMutex = false;
        }
        _cryptoService = new CryptoService(_cryptoDir);
        _fileDialogService = fileDialogService ?? new FileDialogService();
        _promptService = promptService ?? new PromptService();
        _contractDialogService = contractDialogService ?? new ContractDialogService();
        _socketClient = new SocketClientService();
        _socketClient.Dispatch = _dispatch;
        _serverApiClient = new ServerApiClient();
        _contentService = new ContentService(_database, _cryptoDir);

        _hpsPowSkipCosts["upload"] = 4;
        _hpsPowSkipCosts["dns"] = 4;
        _hpsPowSkipCosts["report"] = 4;
        _hpsPowSkipCosts["contract_transfer"] = 4;
        _hpsPowSkipCosts["contract_reset"] = 4;
        _hpsPowSkipCosts["contract_certify"] = 4;
        _hpsPowSkipCosts["usage_contract"] = 4;
        _hpsPowSkipCosts["hps_transfer"] = 4;
        _hpsPowSkipCosts["issuer_recheck"] = 2;

        _hpsPowSkipLabels["upload"] = "upload";
        _hpsPowSkipLabels["dns"] = "registro DNS";
        _hpsPowSkipLabels["report"] = "reporte";
        _hpsPowSkipLabels["contract_transfer"] = "transferencia";
        _hpsPowSkipLabels["contract_reset"] = "invalidação de contrato";
        _hpsPowSkipLabels["contract_certify"] = "certificação de contrato";
        _hpsPowSkipLabels["usage_contract"] = "contrato de uso";
        _hpsPowSkipLabels["hps_transfer"] = "transferência HPS";
        _hpsPowSkipLabels["issuer_recheck"] = "revogação de custódia";

        KnownServers = new ObservableCollection<ServerInfo>();
        DnsRecords = new ObservableCollection<DnsRecord>();
        HpsActionTypes = new ObservableCollection<string>
        {
            "Transferir arquivo",
            "Transferir HPS",
            "Transferir domínio",
            "Transferir API App",
            "Criar/Atualizar API App"
        };
        ContractFilterOptions.Add("all");
        ContractFilterOptions.Add("hash");
        ContractFilterOptions.Add("domain");
        ContractFilterOptions.Add("user");
        ContractFilterOptions.Add("type");
        ContractFilterOptions.Add("title");
        ContractFilterOptions.Add("api_app");
        SearchContentTypes.Add("all");
        SearchContentTypes.Add("image");
        SearchContentTypes.Add("video");
        SearchContentTypes.Add("audio");
        SearchContentTypes.Add("document");
        SearchContentTypes.Add("text");
        SearchSortOptions.Add("reputation");
        SearchSortOptions.Add("recent");
        SearchSortOptions.Add("popular");
        SelectedHpsAction = HpsActionTypes[0];
        NetworkNodes = new ObservableCollection<NetworkNodeInfo>();
        _networkNodesView = new DataGridCollectionView(NetworkNodes);
        _networkNodesView.Filter = FilterNetworkNode;
        InitializeIdentity();
        BuildTourSteps();
        UpdateTourStep();
        RefreshDiskUsage();
        InitializeSessionStats();
        StartSessionTimer();

        EnterNetworkCommand = new AsyncRelayCommand(() => EnterNetworkAsync(), () => !string.IsNullOrWhiteSpace(ServerAddress));
        ExitNetworkCommand = new AsyncRelayCommand(ExitNetworkAsync);
        AddServerCommand = new RelayCommand(AddServer, () => !string.IsNullOrWhiteSpace(NewServerAddress));
        RemoveServerCommand = new RelayCommand(RemoveSelectedServer, () => SelectedServer is not null);
        ConnectServerCommand = new RelayCommand(ConnectSelectedServer, () => SelectedServer is not null);
        RefreshServersCommand = new AsyncRelayCommand(RefreshServersAsync);
        GenerateKeysCommand = new RelayCommand(GenerateNewKeys);
        ExportKeysCommand = new AsyncRelayCommand(ExportKeysAsync);
        ImportKeysCommand = new AsyncRelayCommand(ImportKeysAsync);
        SavePowSettingsCommand = new RelayCommand(SavePowSettings);
        RefreshServerPriceSettingsCommand = new AsyncRelayCommand(RequestServerPriceSettingsAsync, () => IsLoggedIn && _socketClient.IsConnected);
        SaveServerPriceSettingsCommand = new AsyncRelayCommand(UpdateServerPriceSettingsAsync, () => IsLoggedIn && _socketClient.IsConnected && CanManageServerPrices);
        RefreshImcHpsCommand = new AsyncRelayCommand(RefreshImcHpsAsync, () => !string.IsNullOrWhiteSpace(ServerAddress));
        RefreshMessageStateCommand = new AsyncRelayCommand(RequestMessageStateAsync, () => IsLoggedIn && _socketClient.IsConnected);
        RequestMessageContactCommand = new AsyncRelayCommand(RequestMessageContactAsync, () => IsLoggedIn && _socketClient.IsConnected && !string.IsNullOrWhiteSpace(MessageTargetUser));
        SendMessageCommand = new AsyncRelayCommand(SendMessageAsync, () => IsLoggedIn && _socketClient.IsConnected && !string.IsNullOrWhiteSpace(MessageTargetUser) && !string.IsNullOrWhiteSpace(MessageComposeText));
        ApplyMessageTokenSuggestionCommand = new RelayCommand(ApplyMessageTokenSuggestion);
        AcceptMessageContactCommand = new AsyncRelayCommand(AcceptMessageContactAsync, () => SelectedIncomingMessageRequest is not null);
        RejectMessageContactCommand = new AsyncRelayCommand(RejectMessageContactAsync, () => SelectedIncomingMessageRequest is not null);
        ResolveDnsCommand = new AsyncRelayCommand(ResolveDnsAsync, () => !string.IsNullOrWhiteSpace(DnsDomain));
        RegisterDnsCommand = new AsyncRelayCommand(RegisterDnsAsync, () => !string.IsNullOrWhiteSpace(DnsDomain) && !string.IsNullOrWhiteSpace(DnsContentHash));
        SelectDnsFileCommand = new AsyncRelayCommand(SelectDnsFileAsync);
        NavigateCommand = new AsyncRelayCommand(NavigateAsync, () => !string.IsNullOrWhiteSpace(BrowserUrl));
        ShowBrowserSecurityCommand = new AsyncRelayCommand(ShowBrowserSecurityAsync);
        CloseCriticalBrowserErrorCommand = new RelayCommand(CloseCriticalBrowserError);
        ResolveCriticalBrowserErrorCommand = new AsyncRelayCommand(ResolveCriticalBrowserErrorAsync, () => CanResolveCriticalBrowserError);
        ShowDnsSecurityCommand = new AsyncRelayCommand(ShowDnsSecurityAsync);
        SelectUploadFileCommand = new AsyncRelayCommand(SelectUploadFileAsync);
        UploadCommand = new AsyncRelayCommand(UploadAsync, () => !string.IsNullOrWhiteSpace(UploadFilePath) && !string.IsNullOrWhiteSpace(UploadTitle));
        CopyUploadHashCommand = new AsyncRelayCommand(CopyUploadHashAsync, () => !string.IsNullOrWhiteSpace(UploadHash));
        ConfirmExchangeCommand = new AsyncRelayCommand(ConfirmExchangeAsync, () => !string.IsNullOrWhiteSpace(_pendingExchangeQuoteId));
        RequestExchangeQuoteCommand = new AsyncRelayCommand(RequestExchangeQuoteAsync, () => SelectedExchangeIssuer is not null);
        OpenDkvhpsLineageDetailsCommand = new AsyncRelayCommand(OpenDkvhpsLineageDetailsAsync, () => SelectedDkvhpsLineage is not null);
        OpenDkvhpsVoucherDetailsCommand = new AsyncRelayCommand(OpenDkvhpsVoucherDetailsAsync, () => SelectedDkvhpsVoucher is not null);
        OpenDkvhpsLineageVouchersCommand = new AsyncRelayCommand(OpenDkvhpsLineageVouchersAsync, () => SelectedDkvhpsLineage is not null);
        SearchContractsCommand = new AsyncRelayCommand(SearchContractsAsync);
        PreviousContractsPageCommand = new RelayCommand(PreviousContractsPage, () => ContractCurrentPage > 1);
        NextContractsPageCommand = new AsyncRelayCommand(NextContractsPageAsync, CanGoNextContractsPage);
        ClearContractsCommand = new RelayCommand(ClearContracts);
        OpenContractAnalyzerCommand = new RelayCommand(OpenContractAnalyzer, () => SelectedContract is not null);
        RefreshPendingTransfersCommand = new AsyncRelayCommand(RefreshPendingTransfersAsync);
        AcceptTransferCommand = new AsyncRelayCommand(AcceptTransferAsync, () => !string.IsNullOrWhiteSpace(_pendingTransferId));
        RejectTransferCommand = new AsyncRelayCommand(RejectTransferAsync, () => !string.IsNullOrWhiteSpace(_pendingTransferId));
        RenounceTransferCommand = new AsyncRelayCommand(RenounceTransferAsync, () => !string.IsNullOrWhiteSpace(_pendingTransferId));
        OpenSearchCommand = new RelayCommand(OpenSearchWindow);
        CloseImportantFlowCommand = new RelayCommand(CloseImportantFlowWindow);
        StartTourCommand = new RelayCommand(StartTour);
        NextTourCommand = new RelayCommand(AdvanceTour, () => _tourIndex < _tourSteps.Count - 1);
        PrevTourCommand = new RelayCommand(BackTour, () => _tourIndex > 0);
        CloseTourCommand = new RelayCommand(CloseTour);
        SearchContentCommand = new AsyncRelayCommand(SearchContentAsync, () => !string.IsNullOrWhiteSpace(SearchQuery));
        ClearSearchCommand = new RelayCommand(ClearSearch);
        CopySearchHashCommand = new AsyncRelayCommand(CopySearchHashAsync, () => SelectedSearchResult is not null);
        OpenSearchResultCommand = new RelayCommand(OpenSelectedSearchResult, () => SelectedSearchResult is not null);
        BackCommand = new RelayCommand(Back, () => _historyIndex > 0);
        ForwardCommand = new RelayCommand(Forward, () => _historyIndex < _history.Count - 1);
        ReloadCommand = new AsyncRelayCommand(ReloadAsync, () => _historyIndex >= 0);
        HomeCommand = new RelayCommand(Home);
        SaveContentCommand = new AsyncRelayCommand(SaveContentAsync, () => _lastContentBytes is not null);
        ApplyHpsActionCommand = new RelayCommand(ApplyHpsAction);
        StartHpsMintCommand = new AsyncRelayCommand(StartHpsMintAsync, () => IsLoggedIn && _socketClient.IsConnected);
        RequestHpsWalletCommand = new AsyncRelayCommand(RequestHpsWalletAsync);
        RequestMinerFineCommand = new AsyncRelayCommand(() => RequestMinerFineAsync(false));
        AnalyzeVouchersCommand = new AsyncRelayCommand(AnalyzeVouchersAsync);
        ClearVoucherAuditCommand = new RelayCommand(ClearVoucherAudit);
        OpenVoucherAuditContractCommand = new AsyncRelayCommand(OpenVoucherAuditContractAsync);
        AnalyzeSpendCommand = new AsyncRelayCommand(AnalyzeSpendAsync);
        ClearSpendAuditCommand = new RelayCommand(ClearSpendAudit);
        OpenSpendContractCommand = new AsyncRelayCommand(OpenSpendContractAsync);
        RefreshPhpsMarketCommand = new AsyncRelayCommand(RefreshPhpsMarketAsync);
        RequestIssuerRecheckCommand = new AsyncRelayCommand(RequestIssuerRecheckAsync);
        FundSelectedPhpsDebtCommand = new AsyncRelayCommand(FundSelectedPhpsDebtAsync, () => SelectedPhpsDebt is not null);
        CancelPowCommand = new RelayCommand(CancelPow);
        ClosePowMonitorCommand = new RelayCommand(ClosePowMonitor);
        RefreshNetworkCommand = new AsyncRelayCommand(RefreshNetworkAsync);
        SyncNetworkCommand = new AsyncRelayCommand(SyncNetworkAsync);
        ShowMyNodeCommand = new AsyncRelayCommand(ShowMyNodeAsync);
        RefreshInventoryCommand = new AsyncRelayCommand(RefreshSelectedInventoryAsync);
        RequestInventoryTransferCommand = new AsyncRelayCommand(RequestSelectedInventoryTransferAsync, () => SelectedRemoteInventoryItem is not null && IsLoggedIn && _socketClient.IsConnected);
        SignNextPendingTransferCommand = new AsyncRelayCommand(SignNextPendingTransferAsync, () => _pendingMinerTransfers.Count > 0);
        AcceptInventoryRequestCommand = new AsyncRelayCommand(AcceptInventoryRequestAsync, () => SelectedInventoryRequest is not null);
        RejectInventoryRequestCommand = new AsyncRelayCommand(RejectInventoryRequestAsync, () => SelectedInventoryRequest is not null);

        _socketClient.Connected += (_, _) => RunOnUi(OnSocketConnected);
        _socketClient.Disconnected += (_, _) => RunOnUi(OnSocketDisconnected);
        _socketClient.Error += (_, error) => RunOnUi(() =>
        {
            LoginStatus = $"Erro de conexão: {error}";
            Status = "Conexao com erro";
            if (ShouldAutoReconnect())
            {
                _ = RecoverSocketAsync("socket_error");
            }
        });
        _socketClient.TrafficUpdated += (_, args) => RunOnUi(() => UpdateTrafficStats(args));

        RegisterSocketHandlers();
    }

    public string Status
    {
        get => _status;
        set => SetProperty(ref _status, value);
    }

    public string User
    {
        get => _user;
        set => SetProperty(ref _user, value);
    }

    public string Reputation
    {
        get => _reputation;
        set => SetProperty(ref _reputation, value);
    }

    public string BanStatus
    {
        get => _banStatus;
        set => SetProperty(ref _banStatus, value);
    }

    public string DiskUsage
    {
        get => _diskUsage;
        set => SetProperty(ref _diskUsage, value);
    }

    public string ServerPriceSettingsText
    {
        get => _serverPriceSettingsText;
        set => SetProperty(ref _serverPriceSettingsText, value);
    }

    public string ServerPriceSettingsStatus
    {
        get => _serverPriceSettingsStatus;
        set => SetProperty(ref _serverPriceSettingsStatus, value);
    }

    public bool CanManageServerPrices
    {
        get => _canManageServerPrices;
        set
        {
            if (SetProperty(ref _canManageServerPrices, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string ServerPriceOwnerLabel
    {
        get => _serverPriceOwnerLabel;
        set => SetProperty(ref _serverPriceOwnerLabel, value);
    }

    public string MessageTargetUser
    {
        get => _messageTargetUser;
        set
        {
            if (SetProperty(ref _messageTargetUser, value))
            {
                var normalized = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
                if (!string.Equals(_selectedMessageTargetOption, normalized, StringComparison.Ordinal))
                {
                    _selectedMessageTargetOption = normalized;
                    RaisePropertyChanged(nameof(SelectedMessageTargetOption));
                }
                UpdateMessageBundleStatusText();
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string MessageComposeText
    {
        get => _messageComposeText;
        set
        {
            if (SetProperty(ref _messageComposeText, value))
            {
                UpdateMessageComposeSuggestions();
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string MessageStatus
    {
        get => _messageStatus;
        set => SetProperty(ref _messageStatus, value);
    }

    public string MessageStatusTitle
    {
        get => _messageStatusTitle;
        set => SetProperty(ref _messageStatusTitle, value);
    }

    public string MessageStatusForeground
    {
        get => _messageStatusForeground;
        set => SetProperty(ref _messageStatusForeground, value);
    }

    public string MessageStatusBackground
    {
        get => _messageStatusBackground;
        set => SetProperty(ref _messageStatusBackground, value);
    }

    public string MessageStatusBorderBrush
    {
        get => _messageStatusBorderBrush;
        set => SetProperty(ref _messageStatusBorderBrush, value);
    }

    public string MessageConversationText
    {
        get => _messageConversationText;
        set => SetProperty(ref _messageConversationText, value);
    }

    public string MessageBundleStatus
    {
        get => _messageBundleStatus;
        set => SetProperty(ref _messageBundleStatus, value);
    }

    public string ImcHpsStatus
    {
        get => _imcHpsStatus;
        set => SetProperty(ref _imcHpsStatus, value);
    }

    public string ImcHpsSummary
    {
        get => _imcHpsSummary;
        set => SetProperty(ref _imcHpsSummary, value);
    }

    public string ImcHpsExplainer
    {
        get => _imcHpsExplainer;
        set => SetProperty(ref _imcHpsExplainer, value);
    }

    public string ImcHpsServerLabel
    {
        get => _imcHpsServerLabel;
        set => SetProperty(ref _imcHpsServerLabel, value);
    }

    public string MessageComposeHelp
    {
        get => _messageComposeHelp;
        set => SetProperty(ref _messageComposeHelp, value);
    }

    public ObservableCollection<MessageContactInfo> MessageContacts => _messageContacts;
    public ObservableCollection<MessageRequestInfo> IncomingMessageRequests => _incomingMessageRequests;
    public ObservableCollection<MessageRequestInfo> OutgoingMessageRequests => _outgoingMessageRequests;
    public ObservableCollection<string> MessageTargetOptions => _messageTargetOptions;
    public ObservableCollection<string> MessageComposeSuggestions => _messageComposeSuggestions;

    public MessageContactInfo? SelectedMessageContact
    {
        get => _selectedMessageContact;
        set
        {
              if (SetProperty(ref _selectedMessageContact, value))
              {
                  if (value is not null)
                  {
                    MessageTargetUser = value.PeerUser;
                      LoadConversationForPeer(value.PeerUser);
                  }
                  RaiseCommandCanExecuteChanged();
              }
          }
      }

    public MessageRequestInfo? SelectedIncomingMessageRequest
    {
        get => _selectedIncomingMessageRequest;
        set
        {
              if (SetProperty(ref _selectedIncomingMessageRequest, value))
              {
                  if (value is not null)
                  {
                    MessageTargetUser = value.PeerUser;
                  }
                  RaiseCommandCanExecuteChanged();
              }
          }
      }

    public string? SelectedMessageTargetOption
    {
        get => _selectedMessageTargetOption;
        set
        {
            if (SetProperty(ref _selectedMessageTargetOption, value) && !string.IsNullOrWhiteSpace(value))
            {
                MessageTargetUser = value;
            }
        }
    }

    public string SessionElapsed
    {
        get => _sessionElapsed;
        set => SetProperty(ref _sessionElapsed, value);
    }

    public string DataSent
    {
        get => _dataSent;
        set => SetProperty(ref _dataSent, value);
    }

    public string DataReceived
    {
        get => _dataReceived;
        set => SetProperty(ref _dataReceived, value);
    }

    public string ContentDownloadedCount
    {
        get => _contentDownloadedLabel;
        set => SetProperty(ref _contentDownloadedLabel, value);
    }

    public string ContentPublishedCount
    {
        get => _contentPublishedLabel;
        set => SetProperty(ref _contentPublishedLabel, value);
    }

    public string DnsRegisteredCount
    {
        get => _dnsRegisteredLabel;
        set => SetProperty(ref _dnsRegisteredLabel, value);
    }

    public string LoginStatus
    {
        get => _loginStatus;
        set => SetProperty(ref _loginStatus, value);
    }

    public string ClientId
    {
        get => _clientId;
        set => SetProperty(ref _clientId, value);
    }

    public string SessionId
    {
        get => _sessionId;
        set => SetProperty(ref _sessionId, value);
    }

    public string NodeId
    {
        get => _nodeId;
        set => SetProperty(ref _nodeId, value);
    }

    public string PublicKeyPem
    {
        get => _publicKeyPem;
        set => SetProperty(ref _publicKeyPem, value);
    }

    public int PowThreads
    {
        get => _powThreads;
        set => SetProperty(ref _powThreads, value);
    }

    public int MaxPowThreads
    {
        get => _maxPowThreads;
        set => SetProperty(ref _maxPowThreads, value);
    }

    public string PowStatus
    {
        get => _powStatus;
        set
        {
            if (SetProperty(ref _powStatus, value) && string.Equals(_importantFlowKind, "pow", StringComparison.OrdinalIgnoreCase))
            {
                UpdateImportantFlowStatus(value);
            }
        }
    }

    public string PowActionType
    {
        get => _powActionType;
        set => SetProperty(ref _powActionType, value);
    }

    public int PowTargetBits
    {
        get => _powTargetBits;
        set => SetProperty(ref _powTargetBits, value);
    }

    public string PowAttempts
    {
        get => _powAttempts;
        set => SetProperty(ref _powAttempts, value);
    }

    public string PowElapsed
    {
        get => _powElapsed;
        set => SetProperty(ref _powElapsed, value);
    }

    public string PowHashrate
    {
        get => _powHashrate;
        set => SetProperty(ref _powHashrate, value);
    }

    public string ServerAddress
    {
        get => _serverAddress;
        set
        {
            if (SetProperty(ref _serverAddress, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string Username
    {
        get => _username;
        set => SetProperty(ref _username, value);
    }

    public string KeyPassphrase
    {
        get => _keyPassphrase;
        set => SetProperty(ref _keyPassphrase, value);
    }

    public bool AutoLogin
    {
        get => _autoLogin;
        set => SetProperty(ref _autoLogin, value);
    }

    public bool SaveKeys
    {
        get => _saveKeys;
        set => SetProperty(ref _saveKeys, value);
    }

    public bool UseSsl
    {
        get => _useSsl;
        set => SetProperty(ref _useSsl, value);
    }

    public bool AutoReconnect
    {
        get => _autoReconnect;
        set => SetProperty(ref _autoReconnect, value);
    }

    public bool AutoSignTransfers
    {
        get => _autoSignTransfers;
        set
        {
            if (SetProperty(ref _autoSignTransfers, value))
            {
                SaveLocalSetting("auto_sign_transfers", value ? "1" : "0");
            }
        }
    }

    public bool AutoAcceptMinerSelection
    {
        get => _autoAcceptMinerSelection;
        set
        {
            if (SetProperty(ref _autoAcceptMinerSelection, value))
            {
                SaveLocalSetting("auto_accept_miner_selection", value ? "1" : "0");
            }
        }
    }

    public string DnsDomain
    {
        get => _dnsDomain;
        set
        {
            if (SetProperty(ref _dnsDomain, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string DnsContentHash
    {
        get => _dnsContentHash;
        set
        {
            if (SetProperty(ref _dnsContentHash, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string DnsStatus
    {
        get => _dnsStatus;
        set
        {
            if (SetProperty(ref _dnsStatus, value) && string.Equals(_importantFlowKind, "dns", StringComparison.OrdinalIgnoreCase))
            {
                UpdateImportantFlowStatus(value);
            }
        }
    }

    public string BrowserUrl
    {
        get => _browserUrl;
        set
        {
            if (SetProperty(ref _browserUrl, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string BrowserContent
    {
        get => _browserContent;
        set => SetProperty(ref _browserContent, value);
    }

    public Bitmap? BrowserImage
    {
        get => _browserImage;
        set => SetProperty(ref _browserImage, value);
    }

    public bool IsBrowserImageVisible
    {
        get => _isBrowserImageVisible;
        set => SetProperty(ref _isBrowserImageVisible, value);
    }

    public bool IsBrowserTextVisible
    {
        get => _isBrowserTextVisible;
        set => SetProperty(ref _isBrowserTextVisible, value);
    }

    public bool IsCriticalBrowserErrorVisible
    {
        get => _isCriticalBrowserErrorVisible;
        set => SetProperty(ref _isCriticalBrowserErrorVisible, value);
    }

    public bool CanResolveCriticalBrowserError
    {
        get => _canResolveCriticalBrowserError;
        set => SetProperty(ref _canResolveCriticalBrowserError, value);
    }

    public string CriticalBrowserErrorCode
    {
        get => _criticalBrowserErrorCode;
        set => SetProperty(ref _criticalBrowserErrorCode, value);
    }

    public string CriticalBrowserErrorTitle
    {
        get => _criticalBrowserErrorTitle;
        set => SetProperty(ref _criticalBrowserErrorTitle, value);
    }

    public string CriticalBrowserErrorMessage
    {
        get => _criticalBrowserErrorMessage;
        set => SetProperty(ref _criticalBrowserErrorMessage, value);
    }

    public string UploadFilePath
    {
        get => _uploadFilePath;
        set
        {
            if (SetProperty(ref _uploadFilePath, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string UploadTitle
    {
        get => _uploadTitle;
        set
        {
            if (SetProperty(ref _uploadTitle, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string UploadDescription
    {
        get => _uploadDescription;
        set => SetProperty(ref _uploadDescription, value);
    }

    public string UploadMimeType
    {
        get => _uploadMimeType;
        set => SetProperty(ref _uploadMimeType, value);
    }

    public string UploadStatus
    {
        get => _uploadStatus;
        set
        {
            if (SetProperty(ref _uploadStatus, value) && string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
            {
                UpdateImportantFlowStatus(value);
            }
        }
    }

    public string UploadHash
    {
        get => _uploadHash;
        set
        {
            if (SetProperty(ref _uploadHash, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public ObservableCollection<Voucher> Vouchers
    {
        get => _vouchers;
        set => SetProperty(ref _vouchers, value);
    }

    public ObservableCollection<DkvhpsLineageInfo> DkvhpsLineages
    {
        get => _dkvhpsLineages;
        set => SetProperty(ref _dkvhpsLineages, value);
    }

    public ObservableCollection<DkvhpsVoucherInfo> DkvhpsLineageVouchers
    {
        get => _dkvhpsLineageVouchers;
        set => SetProperty(ref _dkvhpsLineageVouchers, value);
    }

    public ObservableCollection<FlowStageItem> ImportantFlowStages
    {
        get => _importantFlowStages;
        set => SetProperty(ref _importantFlowStages, value);
    }

    public DkvhpsLineageInfo? SelectedDkvhpsLineage
    {
        get => _selectedDkvhpsLineage;
        set
        {
            if (SetProperty(ref _selectedDkvhpsLineage, value))
            {
                UpdateDkvhpsSelectedLineage();
                (OpenDkvhpsLineageDetailsCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (OpenDkvhpsLineageVouchersCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public DkvhpsVoucherInfo? SelectedDkvhpsVoucher
    {
        get => _selectedDkvhpsVoucher;
        set
        {
            if (SetProperty(ref _selectedDkvhpsVoucher, value))
            {
                UpdateSelectedDkvhpsVoucherDetails();
                (OpenDkvhpsVoucherDetailsCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public string DkvhpsStatus
    {
        get => _dkvhpsStatus;
        set => SetProperty(ref _dkvhpsStatus, value);
    }

    public string DkvhpsLineageDetails
    {
        get => _dkvhpsLineageDetails;
        set => SetProperty(ref _dkvhpsLineageDetails, value);
    }

    public string DkvhpsVoucherDetails
    {
        get => _dkvhpsVoucherDetails;
        set => SetProperty(ref _dkvhpsVoucherDetails, value);
    }

    public string DkvhpsLineageCatalog
    {
        get => _dkvhpsLineageCatalog;
        set => SetProperty(ref _dkvhpsLineageCatalog, value);
    }

    public string HpsBalance
    {
        get => _hpsBalance;
        set => SetProperty(ref _hpsBalance, value);
    }

    public string HpsMintReason
    {
        get => _hpsMintReason;
        set => SetProperty(ref _hpsMintReason, value);
    }

    public string HpsMintStatus
    {
        get => _hpsMintStatus;
        set => SetProperty(ref _hpsMintStatus, value);
    }

    public string ExchangeStatus
    {
        get => _exchangeStatus;
        set => SetProperty(ref _exchangeStatus, value);
    }

    public string ExchangeQuoteMessage
    {
        get => _exchangeQuoteMessage;
        set => SetProperty(ref _exchangeQuoteMessage, value);
    }

    public string HpsWalletAlert
    {
        get => _hpsWalletAlert;
        set => SetProperty(ref _hpsWalletAlert, value);
    }

    public string VoucherAuditInput
    {
        get => _voucherAuditInput;
        set => SetProperty(ref _voucherAuditInput, value);
    }

    public string VoucherAuditSummary
    {
        get => _voucherAuditSummary;
        set => SetProperty(ref _voucherAuditSummary, value);
    }

    public string VoucherAuditDetails
    {
        get => _voucherAuditDetails;
        set => SetProperty(ref _voucherAuditDetails, value);
    }

    public string SpendAuditInput
    {
        get => _spendAuditInput;
        set => SetProperty(ref _spendAuditInput, value);
    }

    public string SpendAuditSummary
    {
        get => _spendAuditSummary;
        set => SetProperty(ref _spendAuditSummary, value);
    }

    public string SpendAuditDetails
    {
        get => _spendAuditDetails;
        set => SetProperty(ref _spendAuditDetails, value);
    }

    public ObservableCollection<ExchangeServerStats> ExchangeServers
    {
        get => _exchangeServers;
        set => SetProperty(ref _exchangeServers, value);
    }

    public ObservableCollection<ExchangeIssuerSummary> ExchangeIssuers
    {
        get => _exchangeIssuers;
        set => SetProperty(ref _exchangeIssuers, value);
    }

    public ExchangeIssuerSummary? SelectedExchangeIssuer
    {
        get => _selectedExchangeIssuer;
        set
        {
            if (SetProperty(ref _selectedExchangeIssuer, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public ObservableCollection<ContractInfo> Contracts
    {
        get => _contracts;
        set => SetProperty(ref _contracts, value);
    }

    public ObservableCollection<PhpsDebtInfo> PhpsMarketItems => _phpsMarketItems;

    public ObservableCollection<PhpsDebtInfo> MyPhpsDebts => _myPhpsDebts;

    public ObservableCollection<string> ContractFilterOptions { get; } = new();

    public ContractInfo? SelectedContract
    {
        get => _selectedContract;
        set
        {
            if (SetProperty(ref _selectedContract, value))
            {
                if (value is not null)
                {
                    var cached = _database.LoadContractRecord(value.ContractId);
                    ContractDetailsText = BuildContractDetails(cached ?? value);
                    _ = _socketClient.EmitAsync("get_contract", new { contract_id = value.ContractId });
                    if (_pendingTransfersByContract.TryGetValue(value.ContractId, out var pendingInfo))
                    {
                        _pendingTransferId = pendingInfo.TransferId;
                        _pendingTransferType = pendingInfo.TransferType;
                    }
                    else
                    {
                        _pendingTransferId = null;
                        _pendingTransferType = null;
                    }
                }
                else
                {
                    _pendingTransferId = null;
                    _pendingTransferType = null;
                }
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string ContractFilter
    {
        get => _contractFilter;
        set => SetProperty(ref _contractFilter, value);
    }

    public string ContractSearchValue
    {
        get => _contractSearchValue;
        set => SetProperty(ref _contractSearchValue, value);
    }

    public string ContractDetailsText
    {
        get => _contractDetailsText;
        set => SetProperty(ref _contractDetailsText, value);
    }

    public string IssuerRecheckStatus
    {
        get => _issuerRecheckStatus;
        set => SetProperty(ref _issuerRecheckStatus, value);
    }

    public string PhpsMarketStatus
    {
        get => _phpsMarketStatus;
        set => SetProperty(ref _phpsMarketStatus, value);
    }

    public string CustodyDebtSummary
    {
        get => _custodyDebtSummary;
        set => SetProperty(ref _custodyDebtSummary, value);
    }

    public PhpsDebtInfo? SelectedPhpsDebt
    {
        get => _selectedPhpsDebt;
        set
        {
            if (SetProperty(ref _selectedPhpsDebt, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public int ContractCurrentPage
    {
        get => _contractCurrentPage;
        private set
        {
            if (SetProperty(ref _contractCurrentPage, value))
            {
                RaisePropertyChanged(nameof(ContractTotalPages));
                RaisePropertyChanged(nameof(ContractPageStatus));
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public int ContractTotalCount
    {
        get => _contractTotalCount;
        private set
        {
            if (SetProperty(ref _contractTotalCount, value))
            {
                RaisePropertyChanged(nameof(ContractTotalPages));
                RaisePropertyChanged(nameof(ContractPageStatus));
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public int ContractTotalPages => Math.Max(1, (int)Math.Ceiling(ContractTotalCount / (double)ContractChunkSize));

    public string ContractPageStatus =>
        $"Pág. {ContractCurrentPage}/{ContractTotalPages} • exibindo {Contracts.Count} de {ContractTotalCount} contrato(s)";

    public string PendingTransferStatus
    {
        get => _pendingTransferStatus;
        set => SetProperty(ref _pendingTransferStatus, value);
    }

    public string ContractAlertText
    {
        get => _contractAlertText;
        set => SetProperty(ref _contractAlertText, value);
    }

    public bool ContractAlertVisible
    {
        get => _contractAlertVisible;
        set => SetProperty(ref _contractAlertVisible, value);
    }

    public int PendingTransfersCount
    {
        get => _pendingTransfersCount;
        set
        {
            if (SetProperty(ref _pendingTransfersCount, value))
            {
                RaisePropertyChanged(nameof(HasPendingTransfers));
            }
        }
    }

    public bool HasPendingTransfers => PendingTransfersCount > 0;

    public ObservableCollection<PendingTransferInfo> PendingTransfers => _pendingTransfers;

    public PendingTransferInfo? SelectedPendingTransfer
    {
        get => _selectedPendingTransfer;
        set
        {
            if (SetProperty(ref _selectedPendingTransfer, value))
            {
                if (value is not null)
                {
                    _pendingTransferId = value.TransferId;
                    _pendingTransferType = value.TransferType;
                    RaiseCommandCanExecuteChanged();
                }
                else
                {
                    _pendingTransferId = null;
                    _pendingTransferType = null;
                    RaiseCommandCanExecuteChanged();
                }
            }
        }
    }

    public string TransferStatus
    {
        get => _transferStatus;
        set
        {
            if (SetProperty(ref _transferStatus, value) && string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
            {
                UpdateImportantFlowStatus(value);
            }
        }
    }

    public string PowLogText
    {
        get => _powLogText;
        set => SetProperty(ref _powLogText, value);
    }

    public string ImportantFlowTitle
    {
        get => _importantFlowTitle;
        set => SetProperty(ref _importantFlowTitle, value);
    }

    public string ImportantFlowStatus
    {
        get => _importantFlowStatus;
        set => SetProperty(ref _importantFlowStatus, value);
    }

    public string ImportantFlowDetails
    {
        get => _importantFlowDetails;
        set => SetProperty(ref _importantFlowDetails, value);
    }

    public string ImportantFlowLog
    {
        get => _importantFlowLog;
        set => SetProperty(ref _importantFlowLog, value);
    }

    public bool IsImportantFlowBusy
    {
        get => _importantFlowBusy;
        set => SetProperty(ref _importantFlowBusy, value);
    }

    public bool IsImportantFlowCompleted
    {
        get => _isImportantFlowCompleted;
        set => SetProperty(ref _isImportantFlowCompleted, value);
    }

    public bool ImportantFlowCompletedVisible
    {
        get => _importantFlowCompletedVisible;
        set => SetProperty(ref _importantFlowCompletedVisible, value);
    }

    public string ImportantFlowCompletedText
    {
        get => _importantFlowCompletedText;
        set => SetProperty(ref _importantFlowCompletedText, value);
    }

    public bool IsPowActive
    {
        get => _isPowActive;
        set => SetProperty(ref _isPowActive, value);
    }

    public string TourTitle
    {
        get => _tourTitle;
        set => SetProperty(ref _tourTitle, value);
    }

    public string TourBody
    {
        get => _tourBody;
        set => SetProperty(ref _tourBody, value);
    }

    public string TourStepLabel
    {
        get => _tourStepLabel;
        set => SetProperty(ref _tourStepLabel, value);
    }

    public bool ShowTourOnStartup
    {
        get => _showTourOnStartup;
        set
        {
            if (SetProperty(ref _showTourOnStartup, value))
            {
                SaveLocalSetting("show_tour_on_startup", value ? "1" : "0");
            }
        }
    }

    public string PowSolvedCount
    {
        get => _powSolvedCount;
        set => SetProperty(ref _powSolvedCount, value);
    }

    public string PowTotalTime
    {
        get => _powTotalTime;
        set => SetProperty(ref _powTotalTime, value);
    }

    public string HpsMiningStatus
    {
        get => _hpsMiningStatus;
        set => SetProperty(ref _hpsMiningStatus, value);
    }

    public bool IsContinuousMiningEnabled
    {
        get => _isContinuousMiningEnabled;
        set
        {
            if (SetProperty(ref _isContinuousMiningEnabled, value))
            {
                SaveLocalSetting("continuous_mining", value ? "1" : "0");
                if (value)
                {
                    _ = StartContinuousMiningAsync();
                }
            }
        }
    }

    public string HpsMiningBits
    {
        get => _hpsMiningBits;
        set => SetProperty(ref _hpsMiningBits, value);
    }

    public string HpsMiningElapsed
    {
        get => _hpsMiningElapsed;
        set => SetProperty(ref _hpsMiningElapsed, value);
    }

    public string HpsMiningHashrate
    {
        get => _hpsMiningHashrate;
        set => SetProperty(ref _hpsMiningHashrate, value);
    }

    public string HpsMiningAttempts
    {
        get => _hpsMiningAttempts;
        set => SetProperty(ref _hpsMiningAttempts, value);
    }

    public string HpsMiningCount
    {
        get => _hpsMiningCount;
        set => SetProperty(ref _hpsMiningCount, value);
    }

    public string HpsMiningTotalTime
    {
        get => _hpsMiningTotalTime;
        set => SetProperty(ref _hpsMiningTotalTime, value);
    }

    public string MinerPendingSignatures
    {
        get => _minerPendingSignatures;
        set => SetProperty(ref _minerPendingSignatures, value);
    }

    public string MinerFineStatus
    {
        get => _minerFineStatus;
        set => SetProperty(ref _minerFineStatus, value);
    }

    public int MinerPendingFines
    {
        get => _minerPendingFines;
        set => SetProperty(ref _minerPendingFines, value);
    }

    public int MinerPendingDelayFines
    {
        get => _minerPendingDelayFines;
        set => SetProperty(ref _minerPendingDelayFines, value);
    }

    public int MinerSignatureFines
    {
        get => _minerSignatureFines;
        set => SetProperty(ref _minerSignatureFines, value);
    }

    public int MinerFineAmount
    {
        get => _minerFineAmount;
        set => SetProperty(ref _minerFineAmount, value);
    }

    public int MinerFinePerPending
    {
        get => _minerFinePerPending;
        set => SetProperty(ref _minerFinePerPending, value);
    }

    public bool MinerAutoPayFine
    {
        get => _minerAutoPayFine;
        set
        {
            if (SetProperty(ref _minerAutoPayFine, value))
            {
                _ = MaybeAutoPayMinerFineAsync();
            }
        }
    }

    public bool MinerFinePromise
    {
        get => _minerFinePromise;
        set
        {
            if (SetProperty(ref _minerFinePromise, value))
            {
                _ = MaybeAutoPayMinerFineAsync();
            }
        }
    }

    public string MinerWithheldCount
    {
        get => _minerWithheldCount;
        set => SetProperty(ref _minerWithheldCount, value);
    }

    public string MinerWithheldValue
    {
        get => _minerWithheldValue;
        set => SetProperty(ref _minerWithheldValue, value);
    }

    public bool IsLoggedIn
    {
        get => _isLoggedIn;
        set
        {
            if (SetProperty(ref _isLoggedIn, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public int SelectedMainTabIndex
    {
        get => _selectedMainTabIndex;
        set => SetProperty(ref _selectedMainTabIndex, value);
    }

    public ObservableCollection<string> HpsActionTypes { get; }
    public ObservableCollection<string> SearchContentTypes { get; } = new();
    public ObservableCollection<string> SearchSortOptions { get; } = new();

    public string SearchQuery
    {
        get => _searchQuery;
        set
        {
            if (SetProperty(ref _searchQuery, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string SearchContentType
    {
        get => _searchContentType;
        set => SetProperty(ref _searchContentType, value);
    }

    public string SearchSortBy
    {
        get => _searchSortBy;
        set => SetProperty(ref _searchSortBy, value);
    }

    public string SearchStatus
    {
        get => _searchStatus;
        set => SetProperty(ref _searchStatus, value);
    }

    public ObservableCollection<SearchResult> SearchResults
    {
        get => _searchResults;
        set => SetProperty(ref _searchResults, value);
    }

    public SearchResult? SelectedSearchResult
    {
        get => _selectedSearchResult;
        set
        {
            if (SetProperty(ref _selectedSearchResult, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public string SelectedHpsAction
    {
        get => _selectedHpsAction;
        set
        {
            if (SetProperty(ref _selectedHpsAction, value))
            {
                UpdateHpsActionVisibility();
            }
        }
    }

    public string HpsTargetUser
    {
        get => _hpsTargetUser;
        set => SetProperty(ref _hpsTargetUser, value);
    }

    public string HpsAppName
    {
        get => _hpsAppName;
        set => SetProperty(ref _hpsAppName, value);
    }

    public string HpsDomain
    {
        get => _hpsDomain;
        set => SetProperty(ref _hpsDomain, value);
    }

    public string HpsNewOwner
    {
        get => _hpsNewOwner;
        set => SetProperty(ref _hpsNewOwner, value);
    }

    public string HpsContentHash
    {
        get => _hpsContentHash;
        set => SetProperty(ref _hpsContentHash, value);
    }

    public string HpsTransferAmount
    {
        get => _hpsTransferAmount;
        set => SetProperty(ref _hpsTransferAmount, value);
    }

    public string HpsActionStatus
    {
        get => _hpsActionStatus;
        set => SetProperty(ref _hpsActionStatus, value);
    }

    public bool IsHpsActionFile
    {
        get => _isHpsActionFile;
        set => SetProperty(ref _isHpsActionFile, value);
    }

    public bool IsHpsActionHps
    {
        get => _isHpsActionHps;
        set => SetProperty(ref _isHpsActionHps, value);
    }

    public bool IsHpsActionDomain
    {
        get => _isHpsActionDomain;
        set => SetProperty(ref _isHpsActionDomain, value);
    }

    public bool IsHpsActionApiTransfer
    {
        get => _isHpsActionApiTransfer;
        set => SetProperty(ref _isHpsActionApiTransfer, value);
    }

    public bool IsHpsActionApiCreate
    {
        get => _isHpsActionApiCreate;
        set => SetProperty(ref _isHpsActionApiCreate, value);
    }

    public ObservableCollection<NetworkNodeInfo> NetworkNodes { get; }

    public DataGridCollectionView NetworkNodesView => _networkNodesView ?? new DataGridCollectionView(NetworkNodes);

    public string NetworkStats
    {
        get => _networkStats;
        set => SetProperty(ref _networkStats, value);
    }

    public string NetworkStatus
    {
        get => _networkStatus;
        set => SetProperty(ref _networkStatus, value);
    }

    public string NetworkNodeSearch
    {
        get => _networkNodeSearch;
        set
        {
            if (SetProperty(ref _networkNodeSearch, value))
            {
                _networkNodesView?.Refresh();
            }
        }
    }

    public NetworkNodeInfo? SelectedNetworkNode
    {
        get => _selectedNetworkNode;
        set
        {
            if (SetProperty(ref _selectedNetworkNode, value))
            {
                _ = RefreshSelectedInventoryAsync();
            }
        }
    }

    public string InventoryStatus
    {
        get => _inventoryStatus;
        set => SetProperty(ref _inventoryStatus, value);
    }

    public bool InventoryPublic
    {
        get => _inventoryPublic;
        set
        {
            if (SetProperty(ref _inventoryPublic, value))
            {
                SaveLocalSetting("inventory_public", value ? "1" : "0");
            }
        }
    }

    public ObservableCollection<InventoryItem> RemotePublishedInventory => _remotePublishedInventory;
    public ObservableCollection<InventoryItem> RemoteLocalInventory => _remoteLocalInventory;
    public ObservableCollection<InventoryItem> MyInventoryItems => _myInventoryItems;
    public ObservableCollection<InventoryTransferRequest> InventoryRequests => _inventoryRequests;

    public InventoryItem? SelectedRemoteInventoryItem
    {
        get => _selectedRemoteInventoryItem;
        set
        {
            if (SetProperty(ref _selectedRemoteInventoryItem, value))
            {
                (RequestInventoryTransferCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public InventoryItem? SelectedMyInventoryItem
    {
        get => _selectedMyInventoryItem;
        set => SetProperty(ref _selectedMyInventoryItem, value);
    }

    public InventoryTransferRequest? SelectedInventoryRequest
    {
        get => _selectedInventoryRequest;
        set
        {
            if (SetProperty(ref _selectedInventoryRequest, value))
            {
                (AcceptInventoryRequestCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
                (RejectInventoryRequestCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
            }
        }
    }

    public ObservableCollection<ServerInfo> KnownServers { get; }

    public ObservableCollection<DnsRecord> DnsRecords { get; }

    public string NewServerAddress
    {
        get => _newServerAddress;
        set
        {
            if (SetProperty(ref _newServerAddress, value))
            {
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public ServerInfo? SelectedServer
    {
        get => _selectedServer;
        set
        {
            if (SetProperty(ref _selectedServer, value))
            {
                if (value is not null)
                {
                    ServerAddress = value.Address;
                    UseSsl = value.UseSsl;
                }
                RaiseCommandCanExecuteChanged();
            }
        }
    }

    public DnsRecord? SelectedDnsRecord
    {
        get => _selectedDnsRecord;
        set => SetProperty(ref _selectedDnsRecord, value);
    }

    public ICommand EnterNetworkCommand { get; }
    public ICommand ExitNetworkCommand { get; }
    public ICommand AddServerCommand { get; }
    public ICommand RemoveServerCommand { get; }
    public ICommand ConnectServerCommand { get; }
    public ICommand RefreshServersCommand { get; }
    public ICommand GenerateKeysCommand { get; }
    public ICommand ExportKeysCommand { get; }
    public ICommand ImportKeysCommand { get; }
    public ICommand SavePowSettingsCommand { get; }
    public ICommand RefreshImcHpsCommand { get; }
    public ICommand RefreshMessageStateCommand { get; }
    public ICommand RequestMessageContactCommand { get; }
    public ICommand SendMessageCommand { get; }
    public ICommand ApplyMessageTokenSuggestionCommand { get; }
    public ICommand AcceptMessageContactCommand { get; }
    public ICommand RejectMessageContactCommand { get; }
    public ICommand RefreshServerPriceSettingsCommand { get; }
    public ICommand SaveServerPriceSettingsCommand { get; }
    public ICommand ResolveDnsCommand { get; }
    public ICommand RegisterDnsCommand { get; }
    public ICommand SelectDnsFileCommand { get; }
    public ICommand NavigateCommand { get; }
    public ICommand ShowBrowserSecurityCommand { get; }
    public ICommand CloseCriticalBrowserErrorCommand { get; }
    public ICommand ResolveCriticalBrowserErrorCommand { get; }
    public ICommand ShowDnsSecurityCommand { get; }
    public ICommand SelectUploadFileCommand { get; }
    public ICommand UploadCommand { get; }
    public ICommand CopyUploadHashCommand { get; }
    public ICommand ConfirmExchangeCommand { get; }
    public ICommand RequestExchangeQuoteCommand { get; }
    public ICommand OpenDkvhpsLineageDetailsCommand { get; }
    public ICommand OpenDkvhpsVoucherDetailsCommand { get; }
    public ICommand OpenDkvhpsLineageVouchersCommand { get; }
    public ICommand SearchContractsCommand { get; }
    public ICommand PreviousContractsPageCommand { get; }
    public ICommand NextContractsPageCommand { get; }
    public ICommand ClearContractsCommand { get; }
    public ICommand OpenContractAnalyzerCommand { get; }
    public ICommand RefreshPendingTransfersCommand { get; }
    public ICommand AcceptTransferCommand { get; }
    public ICommand RejectTransferCommand { get; }
    public ICommand RenounceTransferCommand { get; }
    public ICommand OpenSearchCommand { get; }
    public ICommand SearchContentCommand { get; }
    public ICommand ClearSearchCommand { get; }
    public ICommand CopySearchHashCommand { get; }
    public ICommand OpenSearchResultCommand { get; }
    public ICommand BackCommand { get; }
    public ICommand ForwardCommand { get; }
    public ICommand ReloadCommand { get; }
    public ICommand HomeCommand { get; }
    public ICommand SaveContentCommand { get; }
    public ICommand ApplyHpsActionCommand { get; }
    public ICommand StartHpsMintCommand { get; }
    public ICommand RequestHpsWalletCommand { get; }
    public ICommand RequestMinerFineCommand { get; }
    public ICommand AnalyzeVouchersCommand { get; }
    public ICommand ClearVoucherAuditCommand { get; }
    public ICommand OpenVoucherAuditContractCommand { get; }
    public ICommand AnalyzeSpendCommand { get; }
    public ICommand ClearSpendAuditCommand { get; }
    public ICommand OpenSpendContractCommand { get; }
    public ICommand RefreshPhpsMarketCommand { get; }
    public ICommand RequestIssuerRecheckCommand { get; }
    public ICommand FundSelectedPhpsDebtCommand { get; }
    public ICommand CancelPowCommand { get; }
    public ICommand ClosePowMonitorCommand { get; }
    public ICommand CloseImportantFlowCommand { get; }
    public ICommand StartTourCommand { get; }
    public ICommand NextTourCommand { get; }
    public ICommand PrevTourCommand { get; }
    public ICommand CloseTourCommand { get; }
    public ICommand RefreshNetworkCommand { get; }
    public ICommand SyncNetworkCommand { get; }
    public ICommand ShowMyNodeCommand { get; }
    public ICommand RefreshInventoryCommand { get; }
    public ICommand RequestInventoryTransferCommand { get; }
    public ICommand SignNextPendingTransferCommand { get; }
    public ICommand AcceptInventoryRequestCommand { get; }
    public ICommand RejectInventoryRequestCommand { get; }

    public Task ConnectCliAsync() => ConnectCliInternalAsync();
    public Task DisconnectCliAsync() => ExitNetworkAsync();

    public void AttachOwner(Window owner)
    {
        _owner = owner;
        RaiseCommandCanExecuteChanged();
        ShowTourIfNeeded();
    }

    public bool HasAnyLocalKeyMaterial()
    {
        return _cryptoService.AnyUserKeyMaterialExists();
    }

    public bool TryUnlockAtStartup(string username, string passphrase, out string errorMessage)
    {
        Username = username?.Trim() ?? string.Empty;
        KeyPassphrase = passphrase ?? string.Empty;
        if (EnsureUserKeysLoaded())
        {
            LoginStatus = "Chaves locais desbloqueadas.";
            errorMessage = string.Empty;
            return true;
        }

        errorMessage = string.IsNullOrWhiteSpace(LoginStatus)
            ? "Falha ao desbloquear chaves locais."
            : LoginStatus;
        return false;
    }

    private void InitializeIdentity()
    {
        SessionId = Guid.NewGuid().ToString();
        NodeId = ComputeNodeId(SessionId);
        ClientId = ComputeClientIdentifier(SessionId);
        PublicKeyPem = string.Empty;
        _localPublicKeyPem = string.Empty;
        _activeKeyUsername = string.Empty;

        MaxPowThreads = Math.Max(1, Environment.ProcessorCount);
        PowThreads = MaxPowThreads;
    }

    private bool EnsureUserKeysLoaded()
    {
        var username = (Username ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(username))
        {
            LoginStatus = "Informe o usuário antes de carregar as chaves.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(KeyPassphrase))
        {
            LoginStatus = "Informe a senha da chave para desbloquear o .hps.key.";
            return false;
        }

        if (_privateKey is not null &&
            string.Equals(_activeKeyUsername, username, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        try
        {
            var (loginKey, loginPublicPem, localPublicPem) = _cryptoService.LoadOrCreateKeys(username, KeyPassphrase);
            var storageKey = _cryptoService.DeriveLocalStorageKey(username, KeyPassphrase);
            var dbSeed = _cryptoService.ReadEncryptedDatabaseSnapshot(_dbPath, storageKey);
            _privateKey?.Dispose();
            _privateKey = loginKey;
            PublicKeyPem = loginPublicPem;
            _localPublicKeyPem = localPublicPem;
            _activeKeyUsername = username;
            _contentService.SetStorageKey(storageKey);
            _contentService.SetDefaultPublicKey(loginPublicPem);
            InitializeDatabaseIfNeeded(dbSeed);
            if (dbSeed is not null)
            {
                CryptographicOperations.ZeroMemory(dbSeed);
            }
            CryptographicOperations.ZeroMemory(storageKey);
            return true;
        }
        catch (Exception ex)
        {
            LoginStatus = "Falha ao desbloquear as chaves: " + ex.Message;
            return false;
        }
    }

    private void InitializeDatabaseIfNeeded(byte[]? dbSeed = null)
    {
        if (_databaseInitialized)
        {
            return;
        }

        _database.Initialize(dbSeed);
        LoadKnownServers();
        LoadDnsRecords();
        LoadLocalVouchers();
        LoadLocalInventory();
        LoadPublishedContentState();
        PowThreads = _database.LoadSettingInt("pow_threads", MaxPowThreads);
        if (PowThreads < 1 || PowThreads > MaxPowThreads)
        {
            PowThreads = MaxPowThreads;
        }
        InventoryPublic = _database.LoadSettingInt("inventory_public", 1) == 1;
        IsContinuousMiningEnabled = _database.LoadSettingInt("continuous_mining", 0) == 1;
        AutoSignTransfers = _database.LoadSettingInt("auto_sign_transfers", 0) == 1;
        AutoAcceptMinerSelection = _database.LoadSettingInt("auto_accept_miner_selection", 0) == 1;
        ShowTourOnStartup = _database.LoadSettingInt("show_tour_on_startup", 1) == 1;
        _databaseInitialized = true;
        LoadLocalMessageContacts();
        SaveKnownServers();
        PersistEncryptedDatabaseSnapshotSafe();
        ShowTourIfNeeded();
    }

    private void LoadPublishedContentState()
    {
        _knownPublishedContentHashes.Clear();
        foreach (var hash in _database.LoadPublishedContentHashes())
        {
            _knownPublishedContentHashes.Add(hash);
        }
    }

    private void RememberPublishedContent(string contentHash)
    {
        if (string.IsNullOrWhiteSpace(contentHash))
        {
            return;
        }

        _database.MarkContentPublished(contentHash);
        _knownPublishedContentHashes.Add(contentHash);
    }

    private bool HasBlockingPowFlow()
    {
        if (IsPowActive)
        {
            return true;
        }

        return _pendingUpload is not null ||
               _pendingDns is not null ||
               _pendingUsageContract is not null ||
               _pendingHpsTransfer is not null ||
               _pendingInventoryTransfer is not null;
    }

    private async Task<bool> PreparePowSlotAsync(string actionType)
    {
        if (!IsPowActive)
        {
            return true;
        }

        if (string.Equals(_lastPowActionType, actionType, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!string.Equals(actionType, "hps_mint", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(_lastPowActionType, "hps_mint", StringComparison.OrdinalIgnoreCase))
        {
            CancelPow();
            await Task.Delay(50);
            return !IsPowActive;
        }

        if (string.Equals(actionType, "hps_mint", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return false;
    }

    private void SaveLocalPublishedContract(string actionType, string contentHash, string domain, string signedContract)
    {
        if (string.IsNullOrWhiteSpace(signedContract))
        {
            return;
        }

        var signature = ExtractSignedContractSignature(signedContract);
        if (string.IsNullOrWhiteSpace(signature))
        {
            return;
        }

        _database.SaveContractRecord(new ContractInfo
        {
            ContractId = Guid.NewGuid().ToString(),
            ActionType = actionType,
            ContentHash = contentHash,
            Domain = domain,
            Username = User,
            Signature = signature,
            Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            Verified = "Sim",
            IntegrityOk = true,
            ContractContent = signedContract
        });
    }

    private static string ExtractSignedContractSignature(string signedContract)
    {
        if (string.IsNullOrWhiteSpace(signedContract))
        {
            return string.Empty;
        }

        foreach (var rawLine in signedContract.Replace("\r\n", "\n").Split('\n'))
        {
            var line = rawLine.Trim();
            if (!line.StartsWith("# SIGNATURE:", StringComparison.Ordinal))
            {
                continue;
            }

            var parts = line.Split(':', 2);
            return parts.Length == 2 ? parts[1].Trim() : string.Empty;
        }

        return string.Empty;
    }

    private Task TryRunDeferredAutoSignAsync()
    {
        LogAutoSign("worker trigger requested");
        EnsurePendingSignatureWorker();
        return Task.CompletedTask;
    }

    private void LogAutoSign(string message)
    {
        var text = $"[auto-sign] {message}";
        Console.WriteLine(text);
        AppendPowLog(text);
    }

    private bool CanSubmitMinerSignature(string transferId)
    {
        if (string.IsNullOrWhiteSpace(transferId))
        {
            return false;
        }
        if (!_submittedMinerTransferAt.TryGetValue(transferId, out var submittedAt))
        {
            return true;
        }

        return DateTimeOffset.UtcNow - submittedAt >= MinerSignatureResubmitCooldown;
    }

    private void EnsurePendingSignatureWorker()
    {
        if (!AutoSignTransfers)
        {
            LogAutoSign("worker skipped: auto-sign disabled");
            return;
        }
        if (string.IsNullOrWhiteSpace(_deferredAutoSignTransferId) && _pendingMinerTransfers.Count == 0)
        {
            LogAutoSign("worker skipped: no pending transfers");
            return;
        }
        if (Interlocked.CompareExchange(ref _pendingSignatureWorkerRunning, 1, 0) != 0)
        {
            LogAutoSign("worker skipped: already running");
            return;
        }
        LogAutoSign($"worker starting deferred={_deferredAutoSignTransferId ?? "<none>"} pending={_pendingMinerTransfers.Count}");
        _ = Task.Run(ProcessPendingSignatureQueueAsync);
    }

    private async Task ProcessPendingSignatureQueueAsync()
    {
        try
        {
            while (AutoSignTransfers)
            {
                if (Interlocked.CompareExchange(ref _signTransferInFlight, 0, 0) != 0)
                {
                    LogAutoSign("worker waiting: sign already in flight");
                    await Task.Delay(50).ConfigureAwait(false);
                    continue;
                }

                var candidateIds = new List<string>();
                if (!string.IsNullOrWhiteSpace(_deferredAutoSignTransferId))
                {
                    candidateIds.Add(_deferredAutoSignTransferId);
                }
                candidateIds.AddRange(_pendingMinerTransfers.Keys.Where(id => !candidateIds.Contains(id, StringComparer.OrdinalIgnoreCase)));

                var transferId = candidateIds.FirstOrDefault(id =>
                    !string.IsNullOrWhiteSpace(id) &&
                    _pendingMinerTransfers.ContainsKey(id) &&
                    CanSubmitMinerSignature(id));

                if (string.IsNullOrWhiteSpace(transferId) || !_pendingMinerTransfers.ContainsKey(transferId))
                {
                    if (_pendingMinerTransfers.Count == 0)
                    {
                        LogAutoSign("worker stopping: queue drained");
                        _deferredAutoSignTransferId = null;
                        return;
                    }

                    LogAutoSign($"worker waiting: no signable candidate deferred={_deferredAutoSignTransferId ?? "<none>"} pending={_pendingMinerTransfers.Count}");
                    await Task.Delay(1000).ConfigureAwait(false);
                    continue;
                }

                _deferredAutoSignTransferId = null;
                LogAutoSign($"worker signing transfer={transferId}");
                await SignTransferByIdAsync(transferId).ConfigureAwait(false);
                await Task.Delay(50).ConfigureAwait(false);
            }
        }
        finally
        {
            Interlocked.Exchange(ref _pendingSignatureWorkerRunning, 0);
            LogAutoSign($"worker stopped auto={AutoSignTransfers} deferred={_deferredAutoSignTransferId ?? "<none>"} pending={_pendingMinerTransfers.Count}");
            if (AutoSignTransfers && (!string.IsNullOrWhiteSpace(_deferredAutoSignTransferId) || _pendingMinerTransfers.Count > 0))
            {
                EnsurePendingSignatureWorker();
            }
        }
    }

    private bool ShouldResumeContinuousMining()
    {
        return IsContinuousMiningEnabled &&
               IsLoggedIn &&
               _socketClient.IsConnected &&
               !HasBlockingPowFlow();
    }

    private void PersistEncryptedDatabaseSnapshot()
    {
        lock (_snapshotPersistenceLock)
        {
            if (Volatile.Read(ref _shutdownSealed) != 0)
            {
                return;
            }

            if (!_databaseInitialized ||
                string.IsNullOrWhiteSpace(_activeKeyUsername) ||
                string.IsNullOrWhiteSpace(KeyPassphrase) ||
                !_ownsDatabaseSnapshotMutex)
            {
                return;
            }

            try
            {
                var dbKey = _cryptoService.DeriveLocalStorageKey(_activeKeyUsername, KeyPassphrase);
                var snapshot = _database.ExportPlaintextBytes();
                if (snapshot.Length > 0)
                {
                    _cryptoService.WriteEncryptedDatabaseSnapshot(_dbPath, dbKey, snapshot);
                    CryptographicOperations.ZeroMemory(snapshot);
                }
                CryptographicOperations.ZeroMemory(dbKey);
            }
            catch
            {
                // Best-effort periodic persistence.
            }
        }
    }

    private void PersistEncryptedDatabaseSnapshotSafe()
    {
        if (Volatile.Read(ref _shutdownSealed) != 0)
        {
            return;
        }

        Interlocked.Exchange(ref _snapshotPersistPending, 1);
        if (Interlocked.CompareExchange(ref _snapshotPersistWorkerRunning, 1, 0) != 0)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    Interlocked.Exchange(ref _snapshotPersistPending, 0);
                    await Task.Delay(150).ConfigureAwait(false);
                    if (Volatile.Read(ref _snapshotPersistPending) != 0)
                    {
                        continue;
                    }

                    try
                    {
                        PersistEncryptedDatabaseSnapshot();
                    }
                    catch
                    {
                        // Best-effort persistence after local state changes.
                    }

                    if (Volatile.Read(ref _snapshotPersistPending) == 0)
                    {
                        break;
                    }
                }
            }
            finally
            {
                Interlocked.Exchange(ref _snapshotPersistWorkerRunning, 0);
                if (Volatile.Read(ref _snapshotPersistPending) != 0)
                {
                    PersistEncryptedDatabaseSnapshotSafe();
                }
            }
        });
    }

    private void LoadKnownServers()
    {
        var preferredAddress = NormalizeServerAddressInput(SelectedServer?.Address);
        if (string.IsNullOrWhiteSpace(preferredAddress))
        {
            preferredAddress = NormalizeServerAddressInput(ServerAddress);
        }
        var preferredUseSsl = SelectedServer?.UseSsl ?? UseSsl;

        var pendingServers = KnownServers
            .Select(s => new ServerInfo
            {
                Address = s.Address,
                UseSsl = s.UseSsl,
                Status = s.Status,
                Reputation = s.Reputation
            })
            .ToList();

        KnownServers.Clear();
        foreach (var (address, useSsl) in _database.LoadKnownServers())
        {
            var normalizedAddress = NormalizeServerAddressInput(address);
            if (string.IsNullOrWhiteSpace(normalizedAddress))
            {
                continue;
            }
            KnownServers.Add(new ServerInfo
            {
                Address = normalizedAddress,
                UseSsl = useSsl,
                Status = "Salvo",
                Reputation = 100
            });
        }

        foreach (var pending in pendingServers)
        {
            var normalizedAddress = NormalizeServerAddressInput(pending.Address);
            if (string.IsNullOrWhiteSpace(normalizedAddress))
            {
                continue;
            }

            if (KnownServers.Any(s => string.Equals(s.Address, normalizedAddress, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            KnownServers.Add(new ServerInfo
            {
                Address = normalizedAddress,
                UseSsl = pending.UseSsl,
                Status = pending.Status,
                Reputation = pending.Reputation
            });
        }

        if (KnownServers.Count > 0)
        {
            var preferredServer = !string.IsNullOrWhiteSpace(preferredAddress)
                ? KnownServers.FirstOrDefault(s =>
                    string.Equals(s.Address, preferredAddress, StringComparison.OrdinalIgnoreCase) &&
                    s.UseSsl == preferredUseSsl)
                : null;

            preferredServer ??= !string.IsNullOrWhiteSpace(preferredAddress)
                ? KnownServers.FirstOrDefault(s =>
                    string.Equals(s.Address, preferredAddress, StringComparison.OrdinalIgnoreCase))
                : null;

            SelectedServer = preferredServer ?? KnownServers[0];
        }
        else if (!string.IsNullOrWhiteSpace(preferredAddress))
        {
            ServerAddress = preferredAddress;
            UseSsl = preferredUseSsl;
        }
    }

    private void LoadDnsRecords()
    {
        DnsRecords.Clear();
        foreach (var (domain, contentHash, username, verified, ddnsHash) in _database.LoadDnsRecords())
        {
            DnsRecords.Add(new DnsRecord
            {
                Domain = domain,
                ContentHash = contentHash,
                Username = username,
                Verified = verified,
                DdnsHash = ddnsHash
            });
        }
    }

    private void LoadLocalVouchers()
    {
        ApplyLocalVouchers(_database.LoadLocalVouchers());
    }

    private void ApplyLocalVouchers(IEnumerable<Voucher> vouchers)
    {
        var materialized = vouchers.ToList();
        UpdateVoucherPresentation(materialized);
        Vouchers.Clear();
        foreach (var voucher in materialized)
        {
            Vouchers.Add(voucher);
        }
        UpdateHpsBalance();
        RefreshExchangeIssuers();
        RebuildDkvhpsDashboard();
    }

    private async Task HandleWalletSyncAsync(JsonElement payload)
    {
        var rawPayload = payload.GetRawText();
        if (Interlocked.CompareExchange(ref _walletSyncRunning, 1, 0) != 0)
        {
            _queuedWalletSyncPayloadJson = rawPayload;
            return;
        }

        try
        {
            await _walletSyncSemaphore.WaitAsync().ConfigureAwait(false);
            if (payload.TryGetProperty("error", out var errProp))
            {
                var error = errProp.GetString();
                RunOnUi(() => ExchangeStatus = $"Erro carteira HPS: {error}");
                return;
            }

            if (!payload.TryGetProperty("vouchers", out var vouchersProp) || vouchersProp.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            var pendingOffers = new List<JsonElement>();
            if (payload.TryGetProperty("pending_offers", out var pendingOffersProp) && pendingOffersProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var offerElem in pendingOffersProp.EnumerateArray())
                {
                    pendingOffers.Add(offerElem.Clone());
                }
            }

            var syncedVouchers = new List<Voucher>();
            var syncedVoucherIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var voucherElem in vouchersProp.EnumerateArray())
            {
                var voucher = ParseVoucher(voucherElem);
                if (voucher is null)
                {
                    continue;
                }
                syncedVoucherIds.Add(voucher.VoucherId);
                syncedVouchers.Add(voucher);
            }

            var localVouchers = await Task.Run(() =>
            {
                _database.ReplaceVoucherRecords(ServerAddress, syncedVouchers);
                try
                {
                    _contentService.SyncVouchersToStorage(syncedVouchers, _privateKey!);
                }
                catch
                {
                    // Best-effort local encrypted voucher mirror.
                }
                return _database.LoadLocalVouchers();
            }).ConfigureAwait(false);

            RunOnUi(() =>
            {
                ApplyLocalVouchers(localVouchers);
                ResolvePendingHpsPaymentsAfterWalletSync();
                TryFinalizePendingExchangeFromWallet(syncedVoucherIds);
                UpdateAutomaticStateSyncLoop();
            });
            foreach (var pendingOffer in pendingOffers)
            {
                _ = HandleVoucherOfferAsync(pendingOffer);
            }
            PersistEncryptedDatabaseSnapshotSafe();
        }
        finally
        {
            _walletSyncSemaphore.Release();
        }

        Interlocked.Exchange(ref _walletSyncRunning, 0);
        var queued = Interlocked.Exchange(ref _queuedWalletSyncPayloadJson, null);
        if (!string.IsNullOrWhiteSpace(queued))
        {
            using var queuedDoc = JsonDocument.Parse(queued);
            _ = HandleWalletSyncAsync(queuedDoc.RootElement.Clone());
        }
    }

    private void LoadLocalInventory()
    {
        _myInventoryItems.Clear();
        foreach (var (contentHash, title, description, mime, size, username, isPublic) in _database.LoadInventoryItems())
        {
            var item = new InventoryItem
            {
                ContentHash = contentHash,
                Title = title,
                Description = description,
                MimeType = mime,
                Size = size,
                Owner = username,
                Source = "local",
                IsPublic = isPublic
            };
            item.PropertyChanged += OnInventoryItemPropertyChanged;
            _myInventoryItems.Add(item);
        }
    }

    private void OnInventoryItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (sender is not InventoryItem item)
        {
            return;
        }

        if (string.Equals(e.PropertyName, nameof(InventoryItem.IsPublic), StringComparison.Ordinal))
        {
            _database.SaveInventoryVisibility(item.ContentHash, item.IsPublic);
        }
    }

    private bool FilterNetworkNode(object? item)
    {
        if (item is not NetworkNodeInfo node)
        {
            return false;
        }
        var term = NetworkNodeSearch?.Trim();
        if (string.IsNullOrWhiteSpace(term))
        {
            return true;
        }
        return node.NodeId.Contains(term, StringComparison.OrdinalIgnoreCase) ||
               node.Username.Contains(term, StringComparison.OrdinalIgnoreCase) ||
               node.Address.Contains(term, StringComparison.OrdinalIgnoreCase) ||
               node.NodeType.Contains(term, StringComparison.OrdinalIgnoreCase);
    }

    private void UpdateHpsBalance()
    {
        var total = Vouchers.Where(IsVoucherActive)
            .Where(v => !_locallyBlockedSpendVoucherIds.Contains(v.VoucherId))
            .Where(v => v.IsUsable)
            .Sum(v => v.Value);
        var reserved = Vouchers.Where(IsVoucherActive)
            .Where(v => _locallyBlockedSpendVoucherIds.Contains(v.VoucherId))
            .Where(v => v.IsUsable)
            .Sum(v => v.Value);
        var unusable = Vouchers.Where(IsVoucherActive)
            .Where(v => !v.IsUsable)
            .Sum(v => v.Value);
        HpsBalance = reserved > 0
            ? $"{total} HPS disponiveis ({reserved} HPS reservados)"
            : $"{total} HPS";
        HpsWalletAlert = (_pendingHpsPaymentsAwaitingWalletSync.Count > 0 || reserved > 0)
            ? reserved > 0
                ? $"Processando gasto HPS e aguardando troco/sincronizacao automatica da carteira. {reserved} HPS estao reservados temporariamente."
                : "Processando gasto HPS e aguardando troco/sincronizacao automatica da carteira..."
            : unusable > 0
            ? $"Atencao: {unusable} HPS estao em vouchers inutilizaveis neste servidor. Realize o cambio para usar esse saldo."
            : (_ownsDatabaseSnapshotMutex
                ? string.Empty
                : "Aviso: outra instancia do navegador esta usando o mesmo banco local; esta instancia nao grava o snapshot local.");
    }

    private void RebuildDkvhpsDashboard()
    {
        var selectedRoot = SelectedDkvhpsLineage?.LineageRootVoucherId ?? string.Empty;
        var lineages = Vouchers
            .Select(BuildDkvhpsVoucherInfo)
            .Where(info => info is not null)
            .Cast<DkvhpsVoucherInfo>()
            .GroupBy(info => string.IsNullOrWhiteSpace(info.LineageRootVoucherId) ? info.VoucherId : info.LineageRootVoucherId, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(group => group.Max(info => info.LineageDepth))
            .ThenBy(group => group.Key, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var vouchers = group.OrderBy(info => info.LineageDepth).ThenBy(info => info.VoucherId, StringComparer.OrdinalIgnoreCase).ToList();
                var active = vouchers
                    .Where(info => !info.Invalidated &&
                                   !string.Equals(info.Status, "spent", StringComparison.OrdinalIgnoreCase) &&
                                   !string.Equals(info.Status, "ghosted", StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(info => info.LineageDepth)
                    .ThenByDescending(info => info.VoucherId, StringComparer.OrdinalIgnoreCase)
                    .FirstOrDefault() ?? vouchers.LastOrDefault();
                if (active is null)
                {
                    return null;
                }
                var declaredLineageHashes = vouchers
                    .Select(info => info.LineageHash)
                    .Where(hash => !string.IsNullOrWhiteSpace(hash))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                var lineageKey = vouchers.FirstOrDefault(info => info.LineageHashVerified && !string.IsNullOrWhiteSpace(info.LineageKey))?.LineageKey
                    ?? vouchers.FirstOrDefault(info => !string.IsNullOrWhiteSpace(info.LineageKey))?.LineageKey
                    ?? string.Empty;
                var lineageIntegrityOk = declaredLineageHashes.Count <= 1 &&
                    (declaredLineageHashes.Count == 0 || vouchers.Any(info => info.LineageHashVerified));
                var integritySummary = lineageIntegrityOk
                    ? declaredLineageHashes.Count == 0
                        ? "Sem hash de linhagem declarado"
                        : "OK"
                    : declaredLineageHashes.Count > 1
                        ? "Hashes de linhagem conflitantes"
                        : "Hash declarado sem chave local correspondente";
                return new DkvhpsLineageInfo
                {
                    LineageRootVoucherId = group.Key,
                    VoucherCount = vouchers.Count,
                    TotalValue = vouchers.Sum(info => info.Value),
                    ActiveVoucherId = active.VoucherId,
                    ActiveStatus = active.Status,
                    LineageOrigin = vouchers.FirstOrDefault()?.LineageOrigin ?? string.Empty,
                    LineageKey = lineageKey,
                    LineageHashVerified = lineageIntegrityOk,
                    IntegritySummary = integritySummary,
                    DisplaySummary = $"{group.Key} | {active.VoucherId} | {vouchers.Count} voucher(s) | {integritySummary}",
                    Vouchers = vouchers
                };
            })
            .Where(info => info is not null)
            .Cast<DkvhpsLineageInfo>()
            .ToList();

        DkvhpsLineages.Clear();
        foreach (var lineage in lineages)
        {
            DkvhpsLineages.Add(lineage);
        }

        DkvhpsStatus = DkvhpsLineages.Count == 0
            ? "Nenhuma linhagem DKVHPS local encontrada."
            : $"{DkvhpsLineages.Count} linhagem(ns) DKVHPS carregada(s): {string.Join(", ", DkvhpsLineages.Select(item => item.LineageRootVoucherId).Where(id => !string.IsNullOrWhiteSpace(id)).Distinct(StringComparer.OrdinalIgnoreCase))}";
        DkvhpsLineageCatalog = DkvhpsLineages.Count == 0
            ? string.Empty
            : string.Join("\n", DkvhpsLineages.Select(item =>
                $"Root: {item.LineageRootVoucherId} | Ativo: {item.ActiveVoucherId} | Qtd: {item.VoucherCount} | Integridade: {item.IntegritySummary}"));
        if (!string.IsNullOrWhiteSpace(selectedRoot))
        {
            SelectedDkvhpsLineage = DkvhpsLineages.FirstOrDefault(item =>
                string.Equals(item.LineageRootVoucherId, selectedRoot, StringComparison.OrdinalIgnoreCase));
        }
        if (SelectedDkvhpsLineage is null && DkvhpsLineages.Count > 0)
        {
            SelectedDkvhpsLineage = DkvhpsLineages[0];
        }
        else
        {
            UpdateDkvhpsSelectedLineage();
        }
    }

    private DkvhpsVoucherInfo? BuildDkvhpsVoucherInfo(Voucher voucher)
    {
        var payload = NormalizePayload(voucher.Payload);
        var dkvhps = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        var hasDkvhps = false;
        if (payload.TryGetValue("dkvhps", out var dkvhpsRaw) && dkvhpsRaw is Dictionary<string, object> parsed)
        {
            dkvhps = parsed;
            hasDkvhps = true;
        }
        var voucherEncrypted = hasDkvhps && dkvhps.TryGetValue("voucher_owner_encrypted", out var voucherEncRaw) ? Convert.ToString(voucherEncRaw) ?? string.Empty : string.Empty;
        var lineageEncrypted = hasDkvhps && dkvhps.TryGetValue("lineage_owner_encrypted", out var lineageEncRaw) ? Convert.ToString(lineageEncRaw) ?? string.Empty : string.Empty;
        var voucherKey = _privateKey is null ? string.Empty : CryptoUtils.DecryptOaepBase64(_privateKey, voucherEncrypted);
        var lineageKey = _privateKey is null ? string.Empty : CryptoUtils.DecryptOaepBase64(_privateKey, lineageEncrypted);
        var voucherHash = hasDkvhps && dkvhps.TryGetValue("voucher_hash", out var voucherHashRaw) ? Convert.ToString(voucherHashRaw) ?? string.Empty : string.Empty;
        var lineageHash = hasDkvhps && dkvhps.TryGetValue("lineage_hash", out var lineageHashRaw) ? Convert.ToString(lineageHashRaw) ?? string.Empty : string.Empty;
        var voucherHashVerified = string.IsNullOrWhiteSpace(voucherHash) ||
            (!string.IsNullOrWhiteSpace(voucherKey) &&
             string.Equals(_contentService.ComputeSha256HexBytes(Encoding.UTF8.GetBytes(voucherKey)), voucherHash, StringComparison.OrdinalIgnoreCase));
        var lineageHashVerified = string.IsNullOrWhiteSpace(lineageHash) ||
            (!string.IsNullOrWhiteSpace(lineageKey) &&
             string.Equals(_contentService.ComputeSha256HexBytes(Encoding.UTF8.GetBytes(lineageKey)), lineageHash, StringComparison.OrdinalIgnoreCase));
        var voucherHashStatus = !hasDkvhps
            ? "Sem envelope"
            : string.IsNullOrWhiteSpace(voucherHash)
                ? "Sem hash"
                : voucherHashVerified
                    ? "OK"
                    : string.IsNullOrWhiteSpace(voucherKey)
                        ? "Chave indisponível"
                        : "Hash divergente";
        var lineageHashStatus = !hasDkvhps
            ? "Sem envelope"
            : string.IsNullOrWhiteSpace(lineageHash)
                ? "Sem hash"
                : lineageHashVerified
                    ? "OK"
                    : string.IsNullOrWhiteSpace(lineageKey)
                        ? "Chave indisponível"
                        : "Hash divergente";
        return new DkvhpsVoucherInfo
        {
            VoucherId = voucher.VoucherId,
            LineageRootVoucherId = payload.TryGetValue("lineage_root_voucher_id", out var rootRaw) ? Convert.ToString(rootRaw) ?? voucher.VoucherId : voucher.VoucherId,
            LineageParentVoucherId = payload.TryGetValue("lineage_parent_voucher_id", out var parentRaw) ? Convert.ToString(parentRaw) ?? string.Empty : string.Empty,
            LineageParentHash = payload.TryGetValue("lineage_parent_hash", out var parentHashRaw) ? Convert.ToString(parentHashRaw) ?? string.Empty : string.Empty,
            LineageDepth = payload.TryGetValue("lineage_depth", out var depthRaw) ? Convert.ToInt32(depthRaw) : 0,
            LineageOrigin = payload.TryGetValue("lineage_origin", out var originRaw) ? Convert.ToString(originRaw) ?? string.Empty : string.Empty,
            Status = voucher.DisplayStatus,
            Invalidated = voucher.Invalidated,
            Value = voucher.Value,
            VoucherHash = voucherHash,
            LineageHash = lineageHash,
            VoucherOwnerEncrypted = voucherEncrypted,
            LineageOwnerEncrypted = lineageEncrypted,
            VoucherKey = voucherKey,
            LineageKey = lineageKey,
            DkvhpsPresent = hasDkvhps,
            VoucherHashVerified = voucherHashVerified,
            LineageHashVerified = lineageHashVerified,
            VoucherHashStatus = voucherHashStatus,
            LineageHashStatus = lineageHashStatus,
            IntegritySummary = !hasDkvhps
                ? "Envelope DKVHPS ausente"
                : voucherHashStatus == "OK" && lineageHashStatus == "OK"
                    ? "OK"
                    : $"Voucher: {voucherHashStatus}; Linhagem: {lineageHashStatus}"
        };
    }

    private void UpdateDkvhpsSelectedLineage()
    {
        DkvhpsLineageVouchers.Clear();
        SelectedDkvhpsVoucher = null;
        if (SelectedDkvhpsLineage is null)
        {
            DkvhpsLineageDetails = "Selecione uma linhagem para inspecionar os vouchers e os envelopes DKVHPS.";
            DkvhpsVoucherDetails = "Selecione um voucher da linhagem para ver o material descriptografado.";
            return;
        }

        var vouchers = SelectedDkvhpsLineage.Vouchers
            .OrderBy(info => info.LineageDepth)
            .ThenBy(info => info.VoucherId, StringComparer.OrdinalIgnoreCase)
            .ToList();
        foreach (var voucher in vouchers)
        {
            DkvhpsLineageVouchers.Add(voucher);
        }
        if (DkvhpsLineageVouchers.Count > 0)
        {
            SelectedDkvhpsVoucher = DkvhpsLineageVouchers.Last();
        }
        else
        {
            DkvhpsVoucherDetails = "Nenhum voucher disponível nesta linhagem.";
        }

        DkvhpsLineageDetails =
            $"Root: {SelectedDkvhpsLineage.LineageRootVoucherId}\n" +
            $"Origem: {SelectedDkvhpsLineage.LineageOrigin}\n" +
            $"Voucher ativo: {SelectedDkvhpsLineage.ActiveVoucherId}\n" +
            $"Status do ativo: {SelectedDkvhpsLineage.ActiveStatus}\n" +
            $"Quantidade: {SelectedDkvhpsLineage.VoucherCount}\n" +
            $"Total historico: {SelectedDkvhpsLineage.TotalValue} HPS\n" +
            $"Integridade da linhagem: {SelectedDkvhpsLineage.IntegritySummary}\n" +
            $"Chave da linhagem: {SelectedDkvhpsLineage.LineageKey}";
    }

    private void UpdateSelectedDkvhpsVoucherDetails()
    {
        DkvhpsVoucherDetails = SelectedDkvhpsVoucher is null
            ? "Selecione um voucher da linhagem para ver o material descriptografado."
            : BuildDkvhpsVoucherDetailText(SelectedDkvhpsVoucher);
    }

    private async Task OpenDkvhpsLineageDetailsAsync()
    {
        if (_owner is null || SelectedDkvhpsLineage is null)
        {
            return;
        }

        var window = new ContractWindow();
        window.SetReadOnlyContent("DKVHPS: detalhes da linhagem", BuildDkvhpsLineageDetailText(SelectedDkvhpsLineage));
        await window.ShowDialog(_owner);
    }

    private async Task OpenDkvhpsVoucherDetailsAsync()
    {
        if (_owner is null || SelectedDkvhpsVoucher is null)
        {
            return;
        }

        var window = new ContractWindow();
        window.SetReadOnlyContent("DKVHPS: detalhes do voucher", BuildDkvhpsVoucherDetailText(SelectedDkvhpsVoucher));
        await window.ShowDialog(_owner);
    }

    private async Task OpenDkvhpsLineageVouchersAsync()
    {
        if (_owner is null || SelectedDkvhpsLineage is null)
        {
            return;
        }

        var window = new DkvhpsLineageWindow
        {
            DataContext = this
        };
        await window.ShowDialog(_owner);
    }

    private string BuildDkvhpsLineageDetailText(DkvhpsLineageInfo lineage)
    {
        var lines = new List<string>
        {
            "# HPS P2P SERVICE",
            "# DKVHPS LINEAGE INSPECTOR:",
            $"## LINEAGE_ROOT_VOUCHER_ID = {lineage.LineageRootVoucherId}",
            $"## LINEAGE_ORIGIN = {lineage.LineageOrigin}",
            $"## ACTIVE_VOUCHER_ID = {lineage.ActiveVoucherId}",
            $"## ACTIVE_STATUS = {lineage.ActiveStatus}",
            $"## VOUCHER_COUNT = {lineage.VoucherCount}",
            $"## TOTAL_HISTORICAL_VALUE = {lineage.TotalValue}",
            $"## LINEAGE_INTEGRITY = {lineage.IntegritySummary}",
            $"## LINEAGE_DKVHPS = {lineage.LineageKey}",
            "## VOUCHERS:"
        };
        foreach (var voucher in lineage.Vouchers.OrderBy(v => v.LineageDepth).ThenBy(v => v.VoucherId, StringComparer.OrdinalIgnoreCase))
        {
            lines.Add($"### VOUCHER_ID = {voucher.VoucherId}");
            lines.Add($"### DEPTH = {voucher.LineageDepth}");
            lines.Add($"### STATUS = {voucher.Status}");
            lines.Add($"### VALUE = {voucher.Value}");
            lines.Add($"### INTEGRITY = {voucher.IntegritySummary}");
        }
        lines.Add("# :END DKVHPS LINEAGE INSPECTOR");
        return string.Join("\n", lines) + "\n";
    }

    private string BuildDkvhpsVoucherDetailText(DkvhpsVoucherInfo info)
    {
        var voucher = Vouchers.FirstOrDefault(item => string.Equals(item.VoucherId, info.VoucherId, StringComparison.OrdinalIgnoreCase));
        var payloadJson = voucher is null
            ? "{}"
            : JsonSerializer.Serialize(NormalizePayload(voucher.Payload), new JsonSerializerOptions { WriteIndented = true });
        var localPath = Path.Combine(_cryptoDir, "vouchers", info.LineageRootVoucherId, $"{info.VoucherId}.hps");
        var lines = new List<string>
        {
            "# HPS P2P SERVICE",
            "# DKVHPS VOUCHER INSPECTOR:",
            $"## DKVHPS = Descriptografy Key for Vouchers of HPS",
            $"## VOUCHER_ID = {info.VoucherId}",
            $"## LINEAGE_ROOT_VOUCHER_ID = {info.LineageRootVoucherId}",
            $"## LINEAGE_PARENT_VOUCHER_ID = {info.LineageParentVoucherId}",
            $"## LINEAGE_PARENT_HASH = {info.LineageParentHash}",
            $"## LINEAGE_DEPTH = {info.LineageDepth}",
            $"## LINEAGE_ORIGIN = {info.LineageOrigin}",
            $"## STATUS = {info.Status}",
            $"## INVALIDATED = {info.Invalidated}",
            $"## VALUE = {info.Value}",
            $"## DKVHPS_PRESENT = {info.DkvhpsPresent}",
            $"## INTEGRITY_SUMMARY = {info.IntegritySummary}",
            $"## VOUCHER_HASH = {info.VoucherHash}",
            $"## VOUCHER_HASH_STATUS = {info.VoucherHashStatus}",
            $"## LINEAGE_HASH = {info.LineageHash}",
            $"## LINEAGE_HASH_STATUS = {info.LineageHashStatus}",
            $"## VOUCHER_DKVHPS = {info.VoucherKey}",
            $"## LINEAGE_DKVHPS = {info.LineageKey}",
            $"## VOUCHER_OWNER_ENCRYPTED = {info.VoucherOwnerEncrypted}",
            $"## LINEAGE_OWNER_ENCRYPTED = {info.LineageOwnerEncrypted}",
            $"## LOCAL_STORAGE_FILE = {localPath}",
            "## ENCRYPTION_LAYERS = voucher_dkvhps -> lineage_dkvhps -> local_browser_key",
            "## PAYLOAD_JSON_START",
            payloadJson,
            "## PAYLOAD_JSON_END",
            "# :END DKVHPS VOUCHER INSPECTOR"
        };
        return string.Join("\n", lines) + "\n";
    }

    private int GetHpsBalanceValue(string issuer, bool includeLocallyBlocked = false)
    {
        return Vouchers
            .Where(IsVoucherActive)
            .Where(v => includeLocallyBlocked || !_locallyBlockedSpendVoucherIds.Contains(v.VoucherId))
            .Where(v => VoucherMatchesIssuer(v, issuer))
            .Sum(v => v.Value);
    }

    private int GetReservedHpsBalanceValue(string issuer)
    {
        return Vouchers
            .Where(IsVoucherActive)
            .Where(v => VoucherMatchesIssuer(v, issuer))
            .Where(v => _locallyBlockedSpendVoucherIds.Contains(v.VoucherId))
            .Sum(v => v.Value);
    }

    private static bool IsVoucherActive(Voucher voucher)
    {
        if (voucher.Invalidated)
        {
            return false;
        }
        return string.Equals(voucher.Status, "active", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(voucher.Status, "valid", StringComparison.OrdinalIgnoreCase);
    }

    private void UpdateVoucherPresentation(IEnumerable<Voucher> vouchers)
    {
        foreach (var voucher in vouchers)
        {
            voucher.IsUsable = IsVoucherUsableOnCurrentServer(voucher);
            voucher.DisplayStatus = voucher.IsUsable
                ? voucher.Status
                : "unusable - Inutilizavel";
        }
    }

    private bool IsVoucherUsableOnCurrentServer(Voucher voucher)
    {
        if (voucher.Invalidated)
        {
            return false;
        }
        if (string.IsNullOrWhiteSpace(ServerAddress))
        {
            return true;
        }
        return VoucherMatchesIssuer(voucher, ServerAddress);
    }

    private void MarkVouchersGhosted(IEnumerable<string> voucherIds)
    {
        var ids = voucherIds
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (ids.Count == 0)
        {
            return;
        }

        _database.UpdateVoucherStatus(ids, "ghosted", false);
        foreach (var voucher in Vouchers.Where(v => ids.Contains(v.VoucherId, StringComparer.OrdinalIgnoreCase)))
        {
            voucher.Status = "ghosted";
            voucher.Invalidated = false;
            voucher.IsUsable = false;
            voucher.DisplayStatus = "ghosted";
        }
        UpdateHpsBalance();
        RefreshExchangeIssuers();
        PersistEncryptedDatabaseSnapshotSafe();
    }

    private void ClearPendingExchangeSourceVouchers()
    {
        _pendingExchangeSourceVoucherIds.Clear();
    }

    private void GhostPendingExchangeSourceVouchers()
    {
        if (_pendingExchangeSourceVoucherIds.Count == 0)
        {
            return;
        }

        MarkVouchersGhosted(_pendingExchangeSourceVoucherIds);
        ClearPendingExchangeSourceVouchers();
    }

    private bool VoucherMatchesIssuer(Voucher voucher, string issuer)
    {
        if (string.IsNullOrWhiteSpace(issuer))
        {
            return true;
        }
        if (string.Equals(voucher.Issuer, issuer, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var serverKey = GetServerPublicKeyForIssuer(issuer);
        if (string.IsNullOrWhiteSpace(serverKey))
        {
            return false;
        }
        var voucherKey = GetVoucherIssuerPublicKey(voucher);
        if (string.IsNullOrWhiteSpace(voucherKey))
        {
            return false;
        }
        var normalizedVoucher = CryptoUtils.NormalizePublicKey(voucherKey);
        var normalizedServer = CryptoUtils.NormalizePublicKey(serverKey);
        return string.Equals(normalizedVoucher, normalizedServer, StringComparison.OrdinalIgnoreCase);
    }

    private string GetServerPublicKeyForIssuer(string issuer)
    {
        if (_serverPublicKeys.TryGetValue(issuer, out var key) && !string.IsNullOrWhiteSpace(key))
        {
            return key;
        }
        if (!string.IsNullOrWhiteSpace(ServerAddress) && _serverPublicKeys.TryGetValue(ServerAddress, out var fallback))
        {
            return fallback;
        }
        return string.Empty;
    }

    private static string NormalizeServerAddressForPin(string address)
    {
        var trimmed = (address ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return string.Empty;
        }

        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var absoluteUri))
        {
            if (!absoluteUri.IsDefaultPort)
            {
                return $"{absoluteUri.Host}:{absoluteUri.Port}".ToLowerInvariant();
            }
            return absoluteUri.Host.ToLowerInvariant();
        }

        if (!trimmed.Contains("://", StringComparison.Ordinal))
        {
            if (Uri.TryCreate("https://" + trimmed, UriKind.Absolute, out var hostUri))
            {
                if (!hostUri.IsDefaultPort)
                {
                    return $"{hostUri.Host}:{hostUri.Port}".ToLowerInvariant();
                }
                return hostUri.Host.ToLowerInvariant();
            }
        }

        return trimmed.TrimEnd('/').ToLowerInvariant();
    }

    private string LoadPinnedServerPublicKey(string address)
    {
        var normalized = NormalizeServerAddressForPin(address);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return string.Empty;
        }
        return _database.LoadSetting("server_pin:" + normalized) ?? string.Empty;
    }

    private void SavePinnedServerPublicKey(string address, string keyB64)
    {
        var normalized = NormalizeServerAddressForPin(address);
        if (string.IsNullOrWhiteSpace(normalized) || string.IsNullOrWhiteSpace(keyB64))
        {
            return;
        }
        SaveLocalSetting("server_pin:" + normalized, keyB64.Trim());
    }

    private static string NormalizePublicKeyB64ForComparison(string keyB64)
    {
        if (string.IsNullOrWhiteSpace(keyB64))
        {
            return string.Empty;
        }

        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(keyB64.Trim()));
            var normalized = CryptoUtils.NormalizePublicKey(decoded);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                return normalized;
            }
        }
        catch
        {
        }

        return keyB64.Trim();
    }

    private static string GetVoucherIssuerPublicKey(Voucher voucher)
    {
        if (voucher.Payload is null)
        {
            return string.Empty;
        }
        if (voucher.Payload.TryGetValue("issuer_public_key", out var raw))
        {
            return ExtractPayloadString(raw);
        }
        return string.Empty;
    }

    private static string ExtractPayloadString(object? value)
    {
        if (value is null)
        {
            return string.Empty;
        }
        if (value is string text)
        {
            return text;
        }
        if (value is JsonElement json && json.ValueKind == JsonValueKind.String)
        {
            return json.GetString() ?? string.Empty;
        }
        return value.ToString() ?? string.Empty;
    }

    private void RefreshExchangeIssuers()
    {
        var issuerGroups = Vouchers
            .Where(IsVoucherActive)
            .GroupBy(v => v.Issuer, StringComparer.OrdinalIgnoreCase)
            .Select(g => new ExchangeIssuerSummary
            {
                Issuer = g.Key,
                Count = g.Count(),
                Total = g.Sum(v => v.Value)
            })
            .OrderByDescending(g => g.Total)
            .ToList();

        ExchangeIssuers.Clear();
        foreach (var entry in issuerGroups)
        {
            ExchangeIssuers.Add(entry);
        }

        if (ExchangeIssuers.Count > 0 && (SelectedExchangeIssuer is null || !ExchangeIssuers.Contains(SelectedExchangeIssuer)))
        {
            SelectedExchangeIssuer = ExchangeIssuers[0];
        }
    }

    private void UpdateHpsActionVisibility()
    {
        var selected = SelectedHpsAction ?? string.Empty;
        IsHpsActionFile = string.Equals(selected, "Transferir arquivo", StringComparison.OrdinalIgnoreCase);
        IsHpsActionHps = string.Equals(selected, "Transferir HPS", StringComparison.OrdinalIgnoreCase);
        IsHpsActionDomain = string.Equals(selected, "Transferir domínio", StringComparison.OrdinalIgnoreCase);
        IsHpsActionApiTransfer = string.Equals(selected, "Transferir API App", StringComparison.OrdinalIgnoreCase);
        IsHpsActionApiCreate = string.Equals(selected, "Criar/Atualizar API App", StringComparison.OrdinalIgnoreCase);
    }

    private void ApplyHpsAction()
    {
        HpsActionStatus = string.Empty;
        var action = SelectedHpsAction ?? string.Empty;
        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            HpsActionStatus = "Conecte-se à rede primeiro.";
            return;
        }

        if (string.Equals(action, "Transferir arquivo", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(HpsTargetUser))
            {
                HpsActionStatus = "Informe o usuário destino.";
                return;
            }

            if (string.IsNullOrWhiteSpace(HpsContentHash) || HpsContentHash.Trim().Length < 32)
            {
                HpsActionStatus = "Informe o hash do conteúdo para transferir.";
                return;
            }

            var content = _contentService.TryLoadLocalContent(HpsContentHash.Trim());
            if (content is null)
            {
                HpsActionStatus = "Conteúdo não encontrado no cache local. Baixe o arquivo antes de transferir.";
                return;
            }

            var tempDir = Path.Combine(_cryptoDir, "runtime_uploads");
            Directory.CreateDirectory(tempDir);
            var tempPath = Path.Combine(tempDir, $"hps_transfer_{HpsContentHash.Trim()}.dat");
            File.WriteAllBytes(tempPath, content.Data);
            UploadTitle = BuildHpsTransferTitle("file", HpsTargetUser.Trim(), null);
            UploadDescription = content.Description;
            UploadMimeType = content.MimeType;
            UploadFilePath = tempPath;
            SelectedMainTabIndex = 3;
            return;
        }

        if (string.Equals(action, "Transferir API App", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(HpsTargetUser) || string.IsNullOrWhiteSpace(HpsAppName))
            {
                HpsActionStatus = "Informe o usuário destino e o nome do app.";
                return;
            }

            UploadTitle = BuildHpsTransferTitle("api_app", HpsTargetUser.Trim(), HpsAppName.Trim());
            SelectedMainTabIndex = 3;
            return;
        }

        if (string.Equals(action, "Criar/Atualizar API App", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(HpsAppName))
            {
                HpsActionStatus = "Informe o nome do app.";
                return;
            }

            UploadTitle = BuildHpsApiTitle(HpsAppName.Trim());
            SelectedMainTabIndex = 3;
            return;
        }

        if (string.Equals(action, "Transferir domínio", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(HpsDomain) || string.IsNullOrWhiteSpace(HpsNewOwner))
            {
                HpsActionStatus = "Informe o domínio e o novo dono.";
                return;
            }

            UploadTitle = BuildHpsDnsChangeTitle();
            var payload = BuildDomainTransferPayload(HpsDomain.Trim(), HpsNewOwner.Trim());
            var tempDir = Path.Combine(_cryptoDir, "runtime_uploads");
            Directory.CreateDirectory(tempDir);
            var tempPath = Path.Combine(tempDir, $"hps_domain_transfer_{HpsDomain.Trim()}.txt");
            File.WriteAllBytes(tempPath, payload);
            UploadFilePath = tempPath;
            UploadMimeType = "text/plain";
            SelectedMainTabIndex = 3;
            return;
        }

        if (string.Equals(action, "Transferir HPS", StringComparison.OrdinalIgnoreCase))
        {
            _ = StartHpsTransferAsync();
        }
    }

    private void SaveKnownServers()
    {
        if (!_databaseInitialized)
        {
            return;
        }
        var servers = KnownServers.Select(s => (s.Address, s.UseSsl));
        _database.SaveKnownServers(servers);
        PersistEncryptedDatabaseSnapshotSafe();
    }

    private async Task EnterNetworkAsync(bool skipPreflight = false)
    {
        if (string.IsNullOrWhiteSpace(ServerAddress))
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(Username))
        {
            LoginStatus = "Informe o usuário.";
            return;
        }
        if (!EnsureUserKeysLoaded())
        {
            return;
        }

        StartImportantFlow(
            "Abertura segura",
            "Preparando credenciais criptográficas...",
            $"Servidor: {ServerAddress}\nUsuário: {Username}",
            "login");
        Interlocked.Exchange(ref _intentionalDisconnectInFlight, 0);
        Console.WriteLine($"[miner-cli] EnterNetworkAsync server={ServerAddress} ssl={UseSsl}");
        Status = "Conectando...";
        LoginStatus = "Conectando...";
        UpdateImportantFlowStatus("Enviando pedido de conexão para o servidor...");
        IsLoggedIn = false;
        var url = BuildSocketUrl(ServerAddress, UseSsl);
        if (!Uri.TryCreate(url, UriKind.Absolute, out _))
        {
            Status = "Falha ao conectar";
            LoginStatus = $"Falha ao conectar: endereço de servidor inválido ({ServerAddress})";
            return;
        }
        url = NormalizeLocalhostUrl(url);
        LoginStatus = $"Conectando em {url}";
        if (!skipPreflight)
        {
            Console.WriteLine($"[miner-cli] Preflight {url}");
        }
        if (!skipPreflight && !await PreflightSocketIoAsync(url))
        {
            Console.WriteLine("[miner-cli] Preflight falhou");
            UpdateImportantFlowStatus("Falha na verificação prévia do servidor.");
            MarkImportantFlowDone();
            return;
        }
        try
        {
            using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
            Console.WriteLine("[miner-cli] ConnectAsync start");
            await _socketClient.ConnectAsync(url, connectCts.Token);
            Console.WriteLine("[miner-cli] ConnectAsync ok");
            Status = "Conectado (aguardando login)";
            User = "Não logado";
            SaveKnownServers();
            UpdateImportantFlowStatus("Conexão estabelecida. Aguardando autenticação segura.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[miner-cli] ConnectAsync error: {ex.Message}");
            Status = "Falha ao conectar";
            LoginStatus = $"Falha ao conectar: {ex.Message}";
            IsLoggedIn = false;
            UpdateImportantFlowStatus($"Falha ao conectar: {ex.Message}");
            MarkImportantFlowDone();
        }
    }

    private async Task ConnectCliInternalAsync()
    {
        if (string.IsNullOrWhiteSpace(ServerAddress))
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(Username))
        {
            LoginStatus = "Informe o usuário.";
            return;
        }
        if (!EnsureUserKeysLoaded())
        {
            return;
        }

        Console.WriteLine($"[miner-cli] CLI connect server={ServerAddress} ssl={UseSsl}");
        Status = "Conectando...";
        LoginStatus = "Conectando...";
        IsLoggedIn = false;
        var url = BuildSocketUrl(ServerAddress, UseSsl);
        if (!Uri.TryCreate(url, UriKind.Absolute, out _))
        {
            LoginStatus = $"Falha ao conectar: endereço de servidor inválido ({ServerAddress})";
            return;
        }
        url = NormalizeLocalhostUrl(url);
        LoginStatus = $"Conectando em {url}";

        if (TryGetHostPort(url, out var host, out var port))
        {
            var tcpOk = await TryTcpConnectAsync(host, port, TimeSpan.FromSeconds(2));
            Console.WriteLine($"[miner-cli] TCP precheck {host}:{port} ok={tcpOk}");
            if (!tcpOk)
            {
                LoginStatus = "Falha ao conectar: servidor indisponível.";
                return;
            }
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
        try
        {
            Console.WriteLine("[miner-cli] CLI ConnectAsync start");
            var connectTask = Task.Run(() => _socketClient.ConnectAsync(url, cts.Token));
            var completed = await Task.WhenAny(connectTask, Task.Delay(TimeSpan.FromSeconds(6), cts.Token));
            if (completed != connectTask)
            {
                Console.WriteLine("[miner-cli] CLI ConnectAsync timeout");
                await _socketClient.DisconnectAsync();
                LoginStatus = "Falha ao conectar: timeout";
                return;
            }
            await connectTask;
            Console.WriteLine("[miner-cli] CLI ConnectAsync ok");
            Status = "Conectado (aguardando login)";
            User = "Não logado";
            SaveKnownServers();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[miner-cli] CLI ConnectAsync error: {ex.Message}");
            Status = "Falha ao conectar";
            LoginStatus = $"Falha ao conectar: {ex.Message}";
            IsLoggedIn = false;
        }
    }

    private static bool TryGetHostPort(string url, out string host, out int port)
    {
        host = string.Empty;
        port = 0;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return false;
        }
        host = uri.Host;
        port = uri.Port;
        return !string.IsNullOrWhiteSpace(host) && port > 0;
    }

    private static async Task<bool> TryTcpConnectAsync(string host, int port, TimeSpan timeout)
    {
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(host, port);
            var completed = await Task.WhenAny(connectTask, Task.Delay(timeout));
            if (completed != connectTask)
            {
                return false;
            }
            await connectTask;
            return client.Connected;
        }
        catch
        {
            return false;
        }
    }

    private async Task ExitNetworkAsync()
    {
        Interlocked.Exchange(ref _intentionalDisconnectInFlight, 1);
        await _socketClient.DisconnectAsync();
        Status = "Desconectado";
        User = "Não logado";
        LoginStatus = "Saida da rede concluida.";
        IsLoggedIn = false;
    }

    public void SealDatabaseOnShutdown()
    {
        lock (_snapshotPersistenceLock)
        {
            if (Interlocked.Exchange(ref _shutdownSealed, 1) != 0)
            {
                return;
            }

            Interlocked.Exchange(ref _snapshotPersistPending, 0);

            if (_databaseInitialized &&
                !string.IsNullOrWhiteSpace(_activeKeyUsername) &&
                !string.IsNullOrWhiteSpace(KeyPassphrase))
            {
                try
                {
                    var dbKey = _cryptoService.DeriveLocalStorageKey(_activeKeyUsername, KeyPassphrase);
                    var snapshot = _database.ExportPlaintextBytes();
                    if (snapshot.Length > 0)
                    {
                        _cryptoService.WriteEncryptedDatabaseSnapshot(_dbPath, dbKey, snapshot);
                        CryptographicOperations.ZeroMemory(snapshot);
                    }
                    CryptographicOperations.ZeroMemory(dbKey);
                }
                catch
                {
                    // Do not throw on shutdown.
                }

                _database.Close();
                _databaseInitialized = false;
            }

            try
            {
                if (_ownsDatabaseSnapshotMutex)
                {
                    _databaseSnapshotMutex.ReleaseMutex();
                }
            }
            catch
            {
            }

            _databaseSnapshotMutex.Dispose();
        }
    }

    public async Task ShutdownAsync()
    {
        if (Interlocked.CompareExchange(ref _shutdownSealed, 0, 0) != 0)
        {
            return;
        }

        try
        {
            Interlocked.Exchange(ref _intentionalDisconnectInFlight, 1);
            await _socketClient.DisconnectAsync();
        }
        catch
        {
            // Best-effort disconnect on shutdown.
        }
        finally
        {
            SealDatabaseOnShutdown();
        }
    }

    private bool TryEnsureDatabaseReadyForLocalState()
    {
        if (_databaseInitialized)
        {
            return true;
        }

        if (!EnsureUserKeysLoaded())
        {
            if (string.IsNullOrWhiteSpace(LoginStatus))
            {
                LoginStatus = "Informe usuário e senha para desbloquear o banco local.";
            }
            return false;
        }

        return true;
    }

    private static string NormalizeLocalhostUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        {
            return url;
        }

        if (!string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return url;
        }

        var builder = new UriBuilder(uri)
        {
            Host = "127.0.0.1"
        };
        return builder.Uri.ToString().TrimEnd('/');
    }

    private static string NormalizeContentHash(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }
        var trimmed = input.Trim();
        if (trimmed.StartsWith("hps://", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed.Substring("hps://".Length);
        }
        trimmed = trimmed.Trim();
        if (trimmed.Length != 64)
        {
            return string.Empty;
        }
        foreach (var c in trimmed)
        {
            var ok = (c >= '0' && c <= '9') ||
                     (c >= 'a' && c <= 'f') ||
                     (c >= 'A' && c <= 'F');
            if (!ok)
            {
                return string.Empty;
            }
        }
        return trimmed.ToLowerInvariant();
    }

    private async Task<bool> PreflightSocketIoAsync(string url)
    {
        try
        {
            if (!TryBuildSocketIoPollingUri(url, out var requestUri))
            {
                LoginStatus = $"Falha ao conectar: endereço de servidor inválido ({url})";
                return false;
            }

            var handler = new HttpClientHandler
            {
                UseProxy = false,
                Proxy = null
            };
            using var client = new HttpClient(handler);
            Console.WriteLine($"[miner-cli] Preflight GET {requestUri}");
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var response = await client.GetAsync(requestUri, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            if (!response.IsSuccessStatusCode)
            {
                LoginStatus = $"Falha ao conectar: preflight HTTP {(int)response.StatusCode}";
                Console.WriteLine($"[miner-cli] Preflight status {(int)response.StatusCode}");
                return false;
            }
            Console.WriteLine("[miner-cli] Preflight ok");
            return true;
        }
        catch (Exception ex)
        {
            LoginStatus = $"Falha ao conectar: preflight {ex.Message}";
            Console.WriteLine($"[miner-cli] Preflight error: {ex.Message}");
            return false;
        }
    }

    private void AddServer()
    {
        var trimmed = NormalizeServerAddressInput(NewServerAddress);
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            Status = "Falha ao adicionar servidor: endereço inválido.";
            return;
        }

        if (KnownServers.Any(s => string.Equals(s.Address, trimmed, StringComparison.OrdinalIgnoreCase)))
        {
            NewServerAddress = string.Empty;
            return;
        }

        var server = new ServerInfo
        {
            Address = trimmed,
            Status = "Salvo",
            Reputation = 100,
            UseSsl = trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
        };
        try
        {
            KnownServers.Add(server);
            if (SelectedServer is null)
            {
                SelectedServer = server;
            }
            NewServerAddress = string.Empty;
            if (_databaseInitialized)
            {
                SaveKnownServers();
            }
            else
            {
                Status = "Servidor adicionado. Será persistido após desbloquear o banco local.";
            }
        }
        catch (Exception ex)
        {
            Status = $"Falha ao adicionar servidor: {ex.Message}";
        }
    }

    private void RemoveSelectedServer()
    {
        if (SelectedServer is null)
        {
            return;
        }

        KnownServers.Remove(SelectedServer);
        SelectedServer = null;
        SaveKnownServers();
    }

    private void ConnectSelectedServer()
    {
        if (SelectedServer is null)
        {
            return;
        }

        ServerAddress = SelectedServer.Address;
        UseSsl = SelectedServer.UseSsl;
        _ = EnterNetworkAsync();
    }

    private async Task RefreshServersAsync()
    {
        foreach (var server in KnownServers)
        {
            server.Status = "Verificando...";
        }
        RaisePropertyChanged(nameof(KnownServers));

        foreach (var server in KnownServers)
        {
            var info = await _serverApiClient.FetchServerInfoAsync(server.Address, server.UseSsl);
            if (info is null)
            {
                server.Status = "Inativo";
                continue;
            }

            server.Status = "Ativo";
            if (info.Value.TryGetProperty("reputation", out var repProp) && repProp.TryGetInt32(out var rep))
            {
                server.Reputation = rep;
            }
        }

        RaisePropertyChanged(nameof(KnownServers));
    }

    private void RefreshDiskUsage()
    {
        if (!Directory.Exists(_cryptoDir))
        {
            DiskUsage = "0MB/500MB";
            return;
        }

        long totalSize = 0;
        foreach (var file in Directory.EnumerateFiles(_cryptoDir, "*", SearchOption.AllDirectories))
        {
            try
            {
                totalSize += new FileInfo(file).Length;
            }
            catch
            {
                // Ignore files we can't access.
            }
        }

        var usedMb = totalSize / (1024 * 1024);
        DiskUsage = $"{usedMb}MB/500MB";
    }

    private void RaiseCommandCanExecuteChanged()
    {
        (EnterNetworkCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (AddServerCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RemoveServerCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ConnectServerCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ResolveDnsCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RegisterDnsCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (NavigateCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (UploadCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (CopyUploadHashCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (ConfirmExchangeCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RequestExchangeQuoteCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (PreviousContractsPageCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (NextContractsPageCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (OpenContractAnalyzerCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (AcceptTransferCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RejectTransferCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RenounceTransferCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (BackCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ForwardCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (ReloadCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (SaveContentCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (StartHpsMintCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RequestHpsWalletCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (CancelPowCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (SearchContentCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (CopySearchHashCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (OpenSearchResultCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RequestInventoryTransferCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (SignNextPendingTransferCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (AcceptInventoryRequestCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RejectInventoryRequestCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RequestIssuerRecheckCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (FundSelectedPhpsDebtCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RefreshImcHpsCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RefreshMessageStateCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RequestMessageContactCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (SendMessageCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (AcceptMessageContactCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RejectMessageContactCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (RefreshServerPriceSettingsCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
        (SaveServerPriceSettingsCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
    }

    private void SaveLocalSetting(string key, string value, bool persistSnapshot = true)
    {
        if (!_databaseInitialized)
        {
            return;
        }

        _database.SaveSetting(key, value);
        if (persistSnapshot)
        {
            PersistEncryptedDatabaseSnapshotSafe();
        }
    }

    private void GenerateNewKeys()
    {
        var username = (Username ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(username))
        {
            LoginStatus = "Informe o usuário para gerar as chaves.";
            return;
        }
        if (string.IsNullOrWhiteSpace(KeyPassphrase))
        {
            LoginStatus = "Informe a senha da chave para gerar o .hps.key.";
            return;
        }

        try
        {
            var (key, publicPem, localPublicPem) = _cryptoService.GenerateAndPersistKeys(username, KeyPassphrase);
            var storageKey = _cryptoService.DeriveLocalStorageKey(username, KeyPassphrase);
            _privateKey?.Dispose();
            _privateKey = key;
            PublicKeyPem = publicPem;
            _localPublicKeyPem = localPublicPem;
            _activeKeyUsername = username;
            _contentService.SetStorageKey(storageKey);
            _contentService.SetDefaultPublicKey(publicPem);
            CryptographicOperations.ZeroMemory(storageKey);
            LoginStatus = "Novo conjunto de chaves gerado com sucesso.";
        }
        catch (Exception ex)
        {
            LoginStatus = "Falha ao gerar chaves: " + ex.Message;
        }
    }

    private async Task ExportKeysAsync()
    {
        if (_owner is null)
        {
            return;
        }

        var username = (Username ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(KeyPassphrase))
        {
            LoginStatus = "Informe usuário e senha da chave para exportar.";
            return;
        }
        if (!EnsureUserKeysLoaded())
        {
            return;
        }

        var outputPath = await _fileDialogService.SaveFileAsync(_owner, "Exportar chaves", _cryptoDir, $"{username}.keys.hps");
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            return;
        }

        try
        {
            _cryptoService.ExportEncryptedKeyBundle(username, outputPath);
            LoginStatus = "Pacote de chaves exportado com sucesso.";
        }
        catch (Exception ex)
        {
            LoginStatus = "Falha ao exportar chaves: " + ex.Message;
        }
    }

    private async Task ImportKeysAsync()
    {
        if (_owner is null)
        {
            return;
        }

        var inputPath = await _fileDialogService.OpenFileAsync(_owner, "Importar chaves", _cryptoDir);
        if (string.IsNullOrWhiteSpace(inputPath))
        {
            return;
        }

        var username = (Username ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(KeyPassphrase))
        {
            LoginStatus = "Informe usuário e senha da chave para importar.";
            return;
        }

        try
        {
            try
            {
                _cryptoService.ImportEncryptedKeyBundle(username, inputPath, KeyPassphrase);
                if (!EnsureUserKeysLoaded())
                {
                    return;
                }
                LoginStatus = "Pacote de chaves importado e validado.";
            }
            catch
            {
                var (key, publicPem) = _cryptoService.ImportKeys(inputPath);
                _cryptoService.OverwriteLoginKey(username, KeyPassphrase, key);
                var storageKey = _cryptoService.DeriveLocalStorageKey(username, KeyPassphrase);
                _privateKey?.Dispose();
                _privateKey = key;
                PublicKeyPem = publicPem;
                _activeKeyUsername = username;
                _contentService.SetStorageKey(storageKey);
                _contentService.SetDefaultPublicKey(publicPem);
                CryptographicOperations.ZeroMemory(storageKey);
                LoginStatus = "Chave PEM importada e aplicada à chave de login.";
            }
        }
        catch (Exception ex)
        {
            LoginStatus = "Falha ao importar chaves: " + ex.Message;
        }
    }

    private void SavePowSettings()
    {
        if (PowThreads < 1)
        {
            PowThreads = 1;
        }

        if (PowThreads > MaxPowThreads)
        {
            PowThreads = MaxPowThreads;
        }

        SaveLocalSetting("pow_threads", PowThreads.ToString());
    }

    private static string BuildSocketUrl(string serverAddress, bool useSsl)
    {
        var uri = TryBuildServerBaseUri(serverAddress, useSsl);
        return uri?.AbsoluteUri.TrimEnd('/') ?? string.Empty;
    }

    private static string NormalizeServerAddressInput(string? serverAddress)
    {
        if (string.IsNullOrWhiteSpace(serverAddress))
        {
            return string.Empty;
        }

        var trimmed = serverAddress.Trim();
        if (trimmed.StartsWith("ws://", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = "http://" + trimmed.Substring("ws://".Length);
        }
        else if (trimmed.StartsWith("wss://", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = "https://" + trimmed.Substring("wss://".Length);
        }

        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var absolute))
        {
            if (absolute.Scheme is not ("http" or "https") || string.IsNullOrWhiteSpace(absolute.Host))
            {
                return string.Empty;
            }

            var builder = new UriBuilder(absolute)
            {
                Path = string.Empty,
                Query = string.Empty,
                Fragment = string.Empty
            };
            return builder.Uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        }

        trimmed = trimmed.TrimEnd('/');
        if (trimmed.Contains(" ", StringComparison.Ordinal) || trimmed.Contains("\\", StringComparison.Ordinal))
        {
            return string.Empty;
        }
        return trimmed;
    }

    private static Uri? TryBuildServerBaseUri(string serverAddress, bool useSsl)
    {
        var normalized = NormalizeServerAddressInput(serverAddress);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return null;
        }

        var absolute = normalized;
        if (!absolute.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !absolute.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            absolute = $"{(useSsl ? "https" : "http")}://{absolute}";
        }

        if (!Uri.TryCreate(absolute, UriKind.Absolute, out var uri))
        {
            return null;
        }

        if (uri.Scheme is not ("http" or "https") || string.IsNullOrWhiteSpace(uri.Host))
        {
            return null;
        }

        var builder = new UriBuilder(uri)
        {
            Path = string.Empty,
            Query = string.Empty,
            Fragment = string.Empty
        };
        return builder.Uri;
    }

    private static bool TryBuildSocketIoPollingUri(string baseUrl, out Uri requestUri)
    {
        requestUri = default!;
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri))
        {
            return false;
        }

        if (baseUri.Scheme is not ("http" or "https") || string.IsNullOrWhiteSpace(baseUri.Host))
        {
            return false;
        }

        var builder = new UriBuilder(baseUri)
        {
            Path = "/socket.io/",
            Query = $"EIO=4&transport=polling&t={DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}",
            Fragment = string.Empty
        };
        requestUri = builder.Uri;
        return true;
    }

    private static string BuildHpsTransferTitle(string transferType, string targetUser, string? appName)
    {
        if (string.Equals(transferType, "api_app", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(appName))
        {
            return $"(HPS!transfer){{type={transferType}, to={targetUser}, app={appName}}}";
        }
        return $"(HPS!transfer){{type={transferType}, to={targetUser}}}";
    }

    private static string BuildHpsApiTitle(string appName)
    {
        return $"(HPS!api){{app}}:{{\"{appName}\"}}";
    }

    private static string BuildHpsDnsChangeTitle()
    {
        return "(HPS!dns_change){change_dns_owner=true, proceed=true}";
    }

    private byte[] BuildDomainTransferPayload(string domain, string newOwner)
    {
        var username = string.IsNullOrWhiteSpace(User) || string.Equals(User, "Não logado", StringComparison.OrdinalIgnoreCase)
            ? Username.Trim()
            : User;
        var lines = new List<string>
        {
            "# HSYST P2P SERVICE",
            "### START:",
            $"# USER: {username}",
            "### :END START",
            "### DNS:",
            $"# NEW_DNAME: DOMAIN = {domain}",
            $"# NEW_DOWNER: OWNER = {newOwner}",
            "### :END DNS",
            "### MODIFY:",
            "# change_dns_owner = true",
            "# proceed = true",
            "### :END MODIFY"
        };
        return Encoding.UTF8.GetBytes(string.Join("\n", lines));
    }

    private string BuildUsageContractTemplate(string termsText, string contractHash)
    {
        var username = string.IsNullOrWhiteSpace(User) || string.Equals(User, "Não logado", StringComparison.OrdinalIgnoreCase)
            ? Username.Trim()
            : User;
        var lines = new List<string>
        {
            "# HSYST P2P SERVICE",
            "## CONTRACT:",
            "### DETAILS:",
            "# ACTION: accept_usage",
            $"# USAGE_CONTRACT_HASH: {contractHash}",
            "### :END DETAILS",
            "### TERMS:"
        };

        foreach (var line in termsText.Split('\n'))
        {
            lines.Add($"# {line}");
        }

        lines.Add("### :END TERMS");
        lines.Add("### START:");
        lines.Add($"# USER: {username}");
        lines.Add("# SIGNATURE: ");
        lines.Add("### :END START");
        lines.Add("## :END CONTRACT");
        return string.Join("\n", lines) + "\n";
    }

    private async Task HandleUsageContractRequiredAsync(JsonElement payload)
    {
        var contractHash = payload.TryGetProperty("contract_hash", out var hashProp) ? hashProp.GetString() : null;
        var contractText = payload.TryGetProperty("contract_text", out var textProp) ? textProp.GetString() : null;
        if (string.IsNullOrWhiteSpace(contractHash))
        {
            LoginStatus = "Contrato de uso não disponível no servidor.";
            return;
        }

        var template = BuildUsageContractTemplate(contractText ?? string.Empty, contractHash.Trim());
        ContractDialogResult result;
        if (_useUiDispatcher)
        {
            if (_owner is null)
            {
                LoginStatus = "Contrato de uso necessário. Abra o navegador para aceitar.";
                return;
            }
            result = await Dispatcher.UIThread.InvokeAsync(() =>
                _contractDialogService.ShowAsync(_owner, "Contrato de Uso", template,
                    text => _contentService.ApplyContractSignature(text, _privateKey!, Username.Trim())));
        }
        else
        {
            var owner = _owner ?? new Window();
            result = await _contractDialogService.ShowAsync(owner, "Contrato de Uso", template,
                text => _contentService.ApplyContractSignature(text, _privateKey!, Username.Trim()));
        }

        if (!result.Accepted)
        {
            LoginStatus = "Contrato de uso não aceito. Login cancelado.";
            return;
        }

        if (_privateKey is null)
        {
            LoginStatus = "Chave privada não disponível.";
            return;
        }

        _pendingUsageContract = new PendingUsageContract(result.Text);
        LoginStatus = "Contrato de uso aceito. Preparando envio...";
        await RunPowOrHpsAsync(
            "usage_contract",
            () =>
            {
                LoginStatus = "Contrato de uso aceito. Iniciando PoW...";
                return RequestPowChallengeAsync("usage_contract");
            },
            payment =>
            {
                LoginStatus = "Enviando contrato de uso com pagamento HPS...";
                return SubmitPendingUsageContractAsync(0, 0.0, payment.Payload);
            },
            null
        );
    }

    private async Task StartHpsTransferAsync()
    {
        HpsActionStatus = string.Empty;
        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            HpsActionStatus = "Conecte-se à rede para transferir HPS.";
            return;
        }

        var targetUser = HpsTargetUser.Trim();
        if (string.IsNullOrWhiteSpace(targetUser))
        {
            HpsActionStatus = "Informe o usuário destino.";
            return;
        }

        if (!int.TryParse(HpsTransferAmount.Trim(), out var amount) || amount <= 0)
        {
            HpsActionStatus = "Informe um valor HPS válido.";
            return;
        }

        var issuer = ServerAddress ?? string.Empty;
        var (voucherIds, total) = SelectHpsVouchersForCost(amount, issuer);
        if (total < amount)
        {
            HpsActionStatus = $"Saldo HPS insuficiente. Necessário: {amount} HPS.";
            return;
        }

        ReserveLocalVouchers(voucherIds);

        var details = new Dictionary<string, string>
        {
            { "TRANSFER_TO", targetUser },
            { "AMOUNT", amount.ToString() },
            { "VOUCHERS", JsonSerializer.Serialize(voucherIds) }
        };
        var contractText = _contentService.BuildContractTemplate("transfer_hps", details);
        if (_privateKey is null)
        {
            HpsActionStatus = "Chave privada não disponível.";
            ReleaseLocalVouchers(voucherIds);
            return;
        }
        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);
        _pendingHpsTransfer = new PendingHpsTransfer(targetUser, amount, voucherIds, signedContract);
        HpsActionStatus = "Preparando transferência HPS...";
        await RunPowOrHpsAsync(
            "hps_transfer",
            () =>
            {
                HpsActionStatus = "Solicitando PoW para transferência HPS...";
                return RequestPowChallengeAsync("hps_transfer");
            },
            payment =>
            {
                HpsActionStatus = "Enviando transferência HPS com pagamento...";
                return SubmitPendingHpsTransferAsync(0, 0.0, payment.Payload);
            },
            voucherIds
        );
    }

    private async Task StartHpsMintAsync()
    {
        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            HpsMintStatus = "Conecte-se à rede para minerar HPS.";
            _isContinuousMiningInFlight = false;
            return;
        }

        _pendingHpsMintVoucherId = null;
        HpsMintStatus = "Solicitando PoW para mineração...";
        HpsMiningStatus = "Solicitando PoW";
        AppendPowLog("Solicitando desafio de PoW para mineração.");
        await RequestPowChallengeAsync("hps_mint");
    }

    private async Task StartContinuousMiningAsync()
    {
        if (!IsContinuousMiningEnabled || _isContinuousMiningInFlight || HasBlockingPowFlow())
        {
            return;
        }

        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            HpsMiningStatus = "Aguardando conexão";
            return;
        }

        _isContinuousMiningInFlight = true;
        await StartHpsMintAsync();
    }

    private void ScheduleNextContinuousMining()
    {
        _isContinuousMiningInFlight = false;
        if (!IsContinuousMiningEnabled || HasBlockingPowFlow())
        {
            return;
        }
        _ = Task.Run(async () =>
        {
            await Task.Delay(750);
            RunOnUi(() => _ = StartContinuousMiningAsync());
        });
    }

    private async Task RequestMinerFineAsync(bool auto)
    {
        if (_minerFineRequestInFlight || !_socketClient.IsConnected)
        {
            return;
        }
        _minerFineRequestInFlight = true;
        _minerFineRequestSource = auto ? "auto" : "manual";
        MinerFineStatus = auto ? "Verificando multas pendentes..." : "Solicitando multa...";
        await _socketClient.EmitAsync("request_miner_fine", new { });
    }

    private bool CanCoverFineAmount(int fineAmount)
    {
        if (fineAmount <= 0)
        {
            return true;
        }
        var withheld = (int)Math.Round(_minerWithheldValueTotal);
        var neededFromIssued = Math.Max(0, fineAmount - withheld);
        var issuer = ServerAddress ?? string.Empty;
        var balance = GetHpsBalanceValue(issuer);
        return balance >= neededFromIssued;
    }

    private async Task MaybeAutoPayMinerFineAsync()
    {
        if (_minerFineRequestInFlight)
        {
            return;
        }
        if (!MinerAutoPayFine && !MinerFinePromise)
        {
            return;
        }
        if ((MinerPendingFines + MinerSignatureFines + MinerPendingDelayFines) <= 0)
        {
            return;
        }
        if (MinerFineAmount <= 0)
        {
            return;
        }
        if (MinerAutoPayFine && !CanCoverFineAmount(MinerFineAmount))
        {
            MinerFineStatus = "Saldo insuficiente para pagar a multa.";
            return;
        }
        await RequestMinerFineAsync(true);
    }

    private async Task PayMinerFineAsync(int fineAmount, int pendingCount, bool promise)
    {
        if (_privateKey is null)
        {
            MinerFineStatus = "Chave privada não disponível para pagar multa.";
            _minerFineRequestInFlight = false;
            _minerFineRequestSource = string.Empty;
            return;
        }

        var withheldTotal = (int)Math.Round(_minerWithheldValueTotal);
        var useWithheld = withheldTotal > 0 && !promise;
        var neededFromIssued = Math.Max(0, fineAmount - (useWithheld ? withheldTotal : 0));
        var voucherIds = new List<string>();
        if (!promise && neededFromIssued > 0)
        {
            var issuer = ServerAddress ?? string.Empty;
            var (selected, total) = SelectHpsVouchersForCost(neededFromIssued, issuer, null);
            if (total < neededFromIssued)
            {
                MinerFineStatus = "Saldo insuficiente para pagar a multa.";
                _minerFineRequestInFlight = false;
                _minerFineRequestSource = string.Empty;
                return;
            }
            voucherIds = selected;
            ReserveLocalVouchers(voucherIds);
            _pendingMinerFineVoucherIds = new List<string>(voucherIds);
        }

        var details = new Dictionary<string, string>
        {
            { "AMOUNT", fineAmount.ToString() },
            { "PENDING", pendingCount.ToString() }
        };
        var contractText = _contentService.BuildContractTemplate("miner_fine", details);
        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);

        MinerFineStatus = "Enviando pagamento de multa...";
        await _socketClient.EmitAsync("pay_miner_fine", new
        {
            voucher_ids = voucherIds,
            contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract)),
            use_withheld = useWithheld,
            promise
        });
    }

    private void UpdateMinerDebtStatus(JsonElement debtStatus)
    {
        if (debtStatus.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        var pendingSignatures = debtStatus.TryGetProperty("pending_signatures", out var pendingProp) ? pendingProp.GetInt32() : 0;
        MinerPendingSignatures = pendingSignatures.ToString();

        MinerPendingFines = debtStatus.TryGetProperty("pending_fines", out var finesProp) ? finesProp.GetInt32() : 0;
        MinerPendingDelayFines = debtStatus.TryGetProperty("pending_delay_fines", out var delayProp) ? delayProp.GetInt32() : 0;
        MinerSignatureFines = debtStatus.TryGetProperty("signature_fines", out var sigFineProp) ? sigFineProp.GetInt32() : 0;
        MinerFineAmount = debtStatus.TryGetProperty("fine_amount", out var fineAmountProp) ? fineAmountProp.GetInt32() : 0;
        MinerFinePerPending = debtStatus.TryGetProperty("fine_per_pending", out var finePerProp) ? finePerProp.GetInt32() : 0;

        var withheldCount = debtStatus.TryGetProperty("withheld_count", out var withheldCountProp) ? withheldCountProp.GetInt32() : 0;
        var withheldTotal = debtStatus.TryGetProperty("withheld_total", out var withheldTotalProp) ? withheldTotalProp.GetInt32() : 0;
        _minerWithheldCountValue = withheldCount;
        _minerWithheldValueTotal = withheldTotal;
        MinerWithheldCount = withheldCount.ToString();
        MinerWithheldValue = withheldTotal.ToString();

        if ((MinerPendingFines + MinerSignatureFines + MinerPendingDelayFines) > 0)
        {
            MinerFineStatus = $"Multas pendentes: {MinerFineAmount} HPS.";
            HpsMiningStatus = "Multas pendentes";
        }
        else if (pendingSignatures > 0)
        {
            HpsMiningStatus = "Pendências de assinatura";
        }
        _ = MaybeAutoPayMinerFineAsync();
    }

    private async Task RequestHpsWalletAsync()
    {
        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            ExchangeStatus = "Conecte-se à rede primeiro.";
            return;
        }

        await _socketClient.EmitAsync("request_hps_wallet", new { });
    }

    private void QueueAutomaticWalletRefresh()
    {
        QueueAutomaticStateRefresh(wallet: true);
    }

    private void QueueAutomaticPendingTransfersRefresh(bool includeMiner)
    {
        QueueAutomaticStateRefresh(pendingTransfers: true, minerPendingTransfers: includeMiner);
    }

    private void QueueAutomaticStateRefresh(bool wallet = false, bool pendingTransfers = false, bool minerPendingTransfers = false)
    {
        if (wallet)
        {
            Interlocked.Exchange(ref _automaticWalletRefreshPending, 1);
        }
        if (pendingTransfers)
        {
            Interlocked.Exchange(ref _automaticPendingTransfersRefreshPending, 1);
        }
        if (minerPendingTransfers)
        {
            Interlocked.Exchange(ref _automaticMinerPendingTransfersRefreshPending, 1);
        }
        if (Interlocked.CompareExchange(ref _automaticStateRefreshWorkerRunning, 1, 0) != 0)
        {
            return;
        }

        _ = Task.Run(ProcessAutomaticStateRefreshQueueAsync);
    }

    private async Task ProcessAutomaticStateRefreshQueueAsync()
    {
        try
        {
            while (true)
            {
                await Task.Delay(120).ConfigureAwait(false);

                var pendingTransfers = Interlocked.Exchange(ref _automaticPendingTransfersRefreshPending, 0) != 0;
                var minerPendingTransfers = Interlocked.Exchange(ref _automaticMinerPendingTransfersRefreshPending, 0) != 0;
                var wallet = Interlocked.Exchange(ref _automaticWalletRefreshPending, 0) != 0;
                if (!pendingTransfers && !minerPendingTransfers && !wallet)
                {
                    return;
                }

                if (!_socketClient.IsConnected)
                {
                    continue;
                }

                if (pendingTransfers)
                {
                    await _socketClient.EmitAsync("get_pending_transfers", new { }).ConfigureAwait(false);
                }
                if (minerPendingTransfers)
                {
                    await _socketClient.EmitAsync("get_miner_pending_transfers", new { }).ConfigureAwait(false);
                }
                if (wallet)
                {
                    await _socketClient.EmitAsync("request_hps_wallet", new { }).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            Interlocked.Exchange(ref _automaticStateRefreshWorkerRunning, 0);
            if (Volatile.Read(ref _automaticPendingTransfersRefreshPending) != 0 ||
                Volatile.Read(ref _automaticMinerPendingTransfersRefreshPending) != 0 ||
                Volatile.Read(ref _automaticWalletRefreshPending) != 0)
            {
                QueueAutomaticStateRefresh();
            }
        }
    }

    private async Task RequestExchangeQuoteAsync()
    {
        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            ExchangeStatus = "Conecte-se à rede primeiro.";
            return;
        }

        if (_privateKey is null)
        {
            ExchangeStatus = "Chave privada não disponível.";
            return;
        }

        if (SelectedExchangeIssuer is null || string.IsNullOrWhiteSpace(SelectedExchangeIssuer.Issuer))
        {
            ExchangeStatus = "Selecione um emissor para converter.";
            return;
        }

        var issuer = SelectedExchangeIssuer.Issuer;
        var issuerVouchers = Vouchers
            .Where(IsVoucherActive)
            .Where(v => string.Equals(v.Issuer, issuer, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (issuerVouchers.Count == 0)
        {
            ExchangeStatus = "Nenhum voucher disponível para conversão.";
            return;
        }

        if (_owner is null)
        {
            ExchangeStatus = "Janela principal não disponível para confirmar câmbio.";
            return;
        }

        var issuerTotal = issuerVouchers.Sum(v => v.Value);
        var amountInput = await _promptService.PromptTextAsync(
            _owner,
            "Cotação de Câmbio",
            $"Emissor: {issuer}\nSaldo disponível: {issuerTotal} HPS\n\nInforme quanto deseja converter:",
            "Solicitar cotação",
            "Cancelar",
            issuerTotal.ToString(CultureInfo.InvariantCulture));
        if (string.IsNullOrWhiteSpace(amountInput))
        {
            ExchangeStatus = "Cotação cancelada.";
            ClearPendingExchangeSourceVouchers();
            return;
        }
        if (!int.TryParse(amountInput, NumberStyles.Integer, CultureInfo.InvariantCulture, out var requestedAmount) || requestedAmount <= 0)
        {
            ExchangeStatus = "Valor de câmbio inválido.";
            ClearPendingExchangeSourceVouchers();
            return;
        }

        var (selectedVoucherIds, selectedTotal) = SelectHpsVouchersForCost(requestedAmount, issuer);
        if (selectedVoucherIds.Count == 0 || selectedTotal < requestedAmount)
        {
            ExchangeStatus = $"Saldo insuficiente para converter {requestedAmount} HPS com o emissor selecionado.";
            ClearPendingExchangeSourceVouchers();
            return;
        }
        _pendingExchangeSourceVoucherIds.Clear();
        foreach (var voucherId in selectedVoucherIds)
        {
            _pendingExchangeSourceVoucherIds.Add(voucherId);
        }
        var selectedVoucherIdSet = new HashSet<string>(selectedVoucherIds, StringComparer.OrdinalIgnoreCase);
        var vouchers = issuerVouchers.Where(v => selectedVoucherIdSet.Contains(v.VoucherId)).ToList();

        var voucherIds = new List<string>();
        foreach (var voucher in vouchers)
        {
            var payload = NormalizePayload(voucher.Payload);
            if (!payload.TryGetValue("voucher_id", out var idObj))
            {
                continue;
            }
            voucherIds.Add(idObj?.ToString() ?? string.Empty);
        }

        voucherIds = voucherIds.Where(id => !string.IsNullOrWhiteSpace(id)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(id => id, StringComparer.Ordinal).ToList();
        if (voucherIds.Count == 0)
        {
            ExchangeStatus = "Vouchers inválidos para conversão.";
            ClearPendingExchangeSourceVouchers();
            return;
        }

        var targetServer = string.IsNullOrWhiteSpace(ServerAddress) ? string.Empty : ServerAddress;
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
        var proofPayload = new Dictionary<string, object>
        {
            { "issuer", issuer },
            { "target_server", targetServer },
            { "voucher_ids", voucherIds },
            { "timestamp", timestamp }
        };

        var proofJson = JsonSerializer.Serialize(proofPayload);
        using var proofDoc = JsonDocument.Parse(proofJson);
        var canonicalProof = BrowserDatabase.CanonicalizePayload(proofDoc.RootElement);
        var proofSignature = CryptoUtils.SignPayload(_privateKey, canonicalProof);

        var details = new Dictionary<string, string>
        {
            { "ISSUER", issuer },
            { "TARGET_SERVER", targetServer },
            { "VOUCHERS", JsonSerializer.Serialize(voucherIds) },
            { "TIMESTAMP", ((long)timestamp).ToString() },
            { "DKVHPS_DISCLOSURE_HPS_B64", Convert.ToBase64String(Encoding.UTF8.GetBytes(BuildVoucherDkvhpsDisclosure(vouchers))) }
        };
        var contractTemplate = _contentService.BuildContractTemplate("exchange_hps", details);
        var signedContract = _contentService.ApplyContractSignature(contractTemplate, _privateKey, User);
        var signedContractB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract));

        var voucherList = new List<Dictionary<string, object>>();
        foreach (var voucher in vouchers)
        {
            var payload = NormalizePayload(voucher.Payload);
            var signatures = new Dictionary<string, object>
            {
                { "issuer", voucher.IssuerSignature },
                { "owner", voucher.OwnerSignature }
            };
            voucherList.Add(new Dictionary<string, object>
            {
                { "payload", payload },
                { "signatures", signatures }
            });
        }

        await _socketClient.EmitAsync("request_exchange_quote", new
        {
            vouchers = voucherList,
            client_signature = Convert.ToBase64String(proofSignature),
            client_public_key = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem)),
            timestamp,
            target_server = targetServer,
            issuer_address = issuer,
            fallback_report = (object?)null,
            contract_content = signedContractB64
        });

        ExchangeQuoteMessage = $"Solicitando cotação para {requestedAmount} HPS...";
    }

    private (List<string> voucherIds, int total) SelectHpsVouchersForCost(int amount, string issuer)
    {
        return SelectHpsVouchersForCost(amount, issuer, null);
    }

    private (List<string> voucherIds, int total) SelectHpsVouchersForCost(int amount, string issuer, IEnumerable<string>? excludeIds, bool includeLocallyBlocked = false)
    {
        var exclude = excludeIds is null
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(excludeIds.Where(id => !string.IsNullOrWhiteSpace(id)), StringComparer.OrdinalIgnoreCase);
        foreach (var blockedId in _locallyBlockedSpendVoucherIds)
        {
            if (!includeLocallyBlocked)
            {
                exclude.Add(blockedId);
            }
        }

        var candidates = Vouchers
            .Where(IsVoucherActive)
            .Where(v => VoucherMatchesIssuer(v, issuer))
            .Where(v => !exclude.Contains(v.VoucherId))
            .OrderByDescending(v => v.Value)
            .ToList();

        var total = 0;
        var selected = new List<string>();
        foreach (var voucher in candidates)
        {
            selected.Add(voucher.VoucherId);
            total += voucher.Value;
            if (total >= amount)
            {
                break;
            }
        }

        return (selected, total);
    }

    private string BuildVoucherDkvhpsDisclosure(IEnumerable<Voucher> vouchers)
    {
        var disclosure = new List<Dictionary<string, string>>();
        foreach (var voucher in vouchers)
        {
            var payload = NormalizePayload(voucher.Payload);
            if (!payload.TryGetValue("dkvhps", out var dkvhpsRaw) || dkvhpsRaw is not Dictionary<string, object> dkvhps)
            {
                continue;
            }
            var voucherEncrypted = dkvhps.TryGetValue("voucher_owner_encrypted", out var voucherEncRaw) ? Convert.ToString(voucherEncRaw) ?? string.Empty : string.Empty;
            var lineageEncrypted = dkvhps.TryGetValue("lineage_owner_encrypted", out var lineageEncRaw) ? Convert.ToString(lineageEncRaw) ?? string.Empty : string.Empty;
            var voucherKey = CryptoUtils.DecryptOaepBase64(_privateKey!, voucherEncrypted);
            var lineageKey = CryptoUtils.DecryptOaepBase64(_privateKey!, lineageEncrypted);
            disclosure.Add(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["voucher_id"] = voucher.VoucherId,
                ["lineage_root_voucher_id"] = payload.TryGetValue("lineage_root_voucher_id", out var rootRaw) ? Convert.ToString(rootRaw) ?? string.Empty : string.Empty,
                ["voucher_hash"] = dkvhps.TryGetValue("voucher_hash", out var voucherHashRaw) ? Convert.ToString(voucherHashRaw) ?? string.Empty : string.Empty,
                ["lineage_hash"] = dkvhps.TryGetValue("lineage_hash", out var lineageHashRaw) ? Convert.ToString(lineageHashRaw) ?? string.Empty : string.Empty,
                ["voucher_dkvhps"] = voucherKey,
                ["lineage_dkvhps"] = lineageKey
            });
        }
        var lines = new List<string>
        {
            "# HPS P2P SERVICE",
            "# DKVHPS DISCLOSURE:",
            $"## ENTRY_COUNT = {disclosure.Count}"
        };
        for (var i = 0; i < disclosure.Count; i++)
        {
            var prefix = $"## ENTRY_{i + 1}_";
            var entry = disclosure[i];
            lines.Add(prefix + "VOUCHER_ID = " + (entry.TryGetValue("voucher_id", out var voucherId) ? voucherId : string.Empty));
            lines.Add(prefix + "LINEAGE_ROOT_VOUCHER_ID = " + (entry.TryGetValue("lineage_root_voucher_id", out var rootId) ? rootId : string.Empty));
            lines.Add(prefix + "VOUCHER_HASH = " + (entry.TryGetValue("voucher_hash", out var voucherHash) ? voucherHash : string.Empty));
            lines.Add(prefix + "LINEAGE_HASH = " + (entry.TryGetValue("lineage_hash", out var lineageHash) ? lineageHash : string.Empty));
            lines.Add(prefix + "VOUCHER_DKVHPS = " + (entry.TryGetValue("voucher_dkvhps", out var voucherKey) ? voucherKey : string.Empty));
            lines.Add(prefix + "LINEAGE_DKVHPS = " + (entry.TryGetValue("lineage_dkvhps", out var lineageKey) ? lineageKey : string.Empty));
        }
        lines.Add("# :END DKVHPS DISCLOSURE");
        return string.Join("\n", lines) + "\n";
    }

    private sealed record HpsPaymentInfo(object Payload, List<string> VoucherIds);

    private sealed record VoucherSelectionInfo(List<string> VoucherIds, int Total);

    private int GetHpsPowSkipCost(string actionType)
    {
        if (string.IsNullOrWhiteSpace(actionType))
        {
            return 0;
        }
        return _hpsPowSkipCosts.TryGetValue(actionType, out var cost) ? cost : 0;
    }

    private async Task<HpsPaymentInfo?> PrepareHpsPaymentAsync(string actionType, IEnumerable<string>? excludeIds)
    {
        if (_privateKey is null || _owner is null)
        {
            return null;
        }

        var cost = GetHpsPowSkipCost(actionType);
        if (cost <= 0)
        {
            return null;
        }

        var issuer = ServerAddress ?? string.Empty;
        var (voucherIds, total) = SelectHpsVouchersForCost(cost, issuer, excludeIds);
        if (total < cost || voucherIds.Count == 0)
        {
            return null;
        }

        var label = _hpsPowSkipLabels.TryGetValue(actionType, out var text) ? text : actionType;
        var totalBalance = GetHpsBalanceValue(issuer);
        var reservedBalance = GetReservedHpsBalanceValue(issuer);
        var confirmMessage = $"Saldo disponivel: {totalBalance} HPS.\n" +
                             (reservedBalance > 0 ? $"Reservado aguardando troco/sincronizacao: {reservedBalance} HPS.\n" : string.Empty) +
                             $"Usar {cost} HPS para pular o PoW de {label}?\n" +
                             "O custo pode ser menor por subsidio da custodia, com troco.";
        var confirmed = await RunOnUiAsync(() =>
            _promptService.ConfirmAsync(_owner, "Usar saldo HPS", confirmMessage, "Usar HPS", "Cancelar")).ConfigureAwait(false);
        if (!confirmed)
        {
            return null;
        }

        BlockLocalSpendVouchers(voucherIds);
        var details = new Dictionary<string, string>
        {
            { "ACTION_TYPE", actionType },
            { "COST", cost.ToString() },
            { "VOUCHERS", JsonSerializer.Serialize(voucherIds) }
        };
        var contractText = _contentService.BuildContractTemplate("spend_hps", details);
        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);
        var contractB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract));
        var payment = new
        {
            voucher_ids = voucherIds,
            cost,
            action_type = actionType,
            contract_content = contractB64
        };
        return new HpsPaymentInfo(payment, voucherIds);
    }

    private async Task RunPowOrHpsAsync(string actionType, Func<Task> powStart, Func<HpsPaymentInfo, Task> hpsStart, IEnumerable<string>? excludeIds)
    {
        var payment = await PrepareHpsPaymentAsync(actionType, excludeIds);
        if (payment is not null)
        {
            _pendingHpsPayments[actionType] = payment.VoucherIds;
            await hpsStart(payment);
            return;
        }

        var cost = GetHpsPowSkipCost(actionType);
        var issuer = ServerAddress ?? string.Empty;
        var availableBalance = GetHpsBalanceValue(issuer);
        var reservedBalance = GetReservedHpsBalanceValue(issuer);
        var (_, totalIncludingReserved) = SelectHpsVouchersForCost(cost, issuer, excludeIds, includeLocallyBlocked: true);
        if (cost > 0 &&
            availableBalance < cost &&
            reservedBalance > 0 &&
            totalIncludingReserved >= cost &&
            _owner is not null)
        {
            var usePowAnyway = await RunOnUiAsync(() =>
                _promptService.ConfirmAsync(
                    _owner,
                    "Saldo HPS reservado",
                    $"Existe saldo HPS suficiente, mas ele ainda esta reservado aguardando troco/sincronizacao.\n" +
                    $"Disponivel agora: {availableBalance} HPS.\n" +
                    $"Reservado: {reservedBalance} HPS.\n" +
                    "Deseja fazer PoW mesmo assim?",
                    "Fazer PoW",
                    "Aguardar")).ConfigureAwait(false);
            if (!usePowAnyway)
            {
                return;
            }
        }
        await powStart();
    }

    private bool QueueRemoteMessageImcBootstrapIfNeeded(string actionType)
    {
        return false;
    }

    private void ReleasePendingHpsPayment(string actionType)
    {
        if (!_pendingHpsPayments.TryGetValue(actionType, out var voucherIds))
        {
            return;
        }
        UnblockLocalSpendVouchers(voucherIds);
        _pendingHpsPayments.Remove(actionType);
        _pendingHpsPaymentsAwaitingWalletSync.Remove(actionType);
        UpdateAutomaticStateSyncLoop();
    }

    private void ClearPendingHpsPayment(string actionType)
    {
        if (_pendingHpsPayments.ContainsKey(actionType))
        {
            _pendingHpsPaymentsAwaitingWalletSync.Add(actionType);
            UpdateAutomaticStateSyncLoop();
        }
    }

    private void MovePendingHpsPaymentToWalletSync(string actionType)
    {
        if (string.IsNullOrWhiteSpace(actionType))
        {
            return;
        }

        ClearPendingHpsPayment(actionType);
        QueueAutomaticWalletRefresh();
    }

    private static string GetActionTypeFromSpendHpsTransfer(string transferType)
    {
        const string prefix = "spend_hps:";
        if (string.IsNullOrWhiteSpace(transferType) ||
            !transferType.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return string.Empty;
        }

        return transferType[prefix.Length..].Trim().ToLowerInvariant();
    }

    private async Task<VoucherSelectionInfo?> PrepareVoucherSelectionAsync(int amount, string title, string message)
    {
        if (_owner is null || amount <= 0)
        {
            return null;
        }

        var issuer = ServerAddress ?? string.Empty;
        var (voucherIds, total) = SelectHpsVouchersForCost(amount, issuer);
        if (total < amount || voucherIds.Count == 0)
        {
            return null;
        }

        var confirmed = await _promptService.ConfirmAsync(_owner, title, message, "Prosseguir", "Cancelar");
        if (!confirmed)
        {
            return null;
        }

        return new VoucherSelectionInfo(voucherIds, total);
    }

    private void UpdatePowCostsFromPayload(JsonElement payload)
    {
        if (!payload.TryGetProperty("pow_costs", out var powProp) || powProp.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var entry in powProp.EnumerateObject())
        {
            if (entry.Value.ValueKind == JsonValueKind.Number && entry.Value.TryGetInt32(out var intValue))
            {
                _hpsPowSkipCosts[entry.Name] = intValue;
            }
            else if (entry.Value.ValueKind == JsonValueKind.String && int.TryParse(entry.Value.GetString(), out var parsed))
            {
                _hpsPowSkipCosts[entry.Name] = parsed;
            }
        }
    }

    private void ApplyServerPriceSettings(JsonElement payload)
    {
        if (!payload.TryGetProperty("prices", out var pricesProp) || pricesProp.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        var entries = new List<KeyValuePair<string, int>>();
        foreach (var entry in pricesProp.EnumerateObject())
        {
            var key = (entry.Name ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(key))
            {
                continue;
            }

            var value = 0;
            if (entry.Value.ValueKind == JsonValueKind.Number)
            {
                value = entry.Value.GetInt32();
            }
            else if (entry.Value.ValueKind == JsonValueKind.String)
            {
                _ = int.TryParse(entry.Value.GetString(), out value);
            }

            if (value <= 0)
            {
                continue;
            }

            _hpsPowSkipCosts[key] = value;
            entries.Add(new KeyValuePair<string, int>(key, value));
        }

        entries.Sort((a, b) => string.Compare(a.Key, b.Key, StringComparison.OrdinalIgnoreCase));
        ServerPriceSettingsText = string.Join(Environment.NewLine, entries.Select(item => $"{item.Key}={item.Value}"));
        CanManageServerPrices = payload.TryGetProperty("can_manage", out var canManageProp) && canManageProp.GetBoolean();
        var ownerUser = payload.TryGetProperty("owner_user", out var ownerProp) ? ownerProp.GetString() ?? string.Empty : string.Empty;
        var ownerActive = payload.TryGetProperty("owner_active", out var ownerActiveProp) && ownerActiveProp.GetBoolean();
        ServerPriceOwnerLabel = ownerActive
            ? $"Somente o owner do servidor pode alterar os preços. Owner: {ownerUser}"
            : "Servidor sem owner configurado: os preços ficam bloqueados na interface e só podem ser alterados pelo console ou pelo código.";
    }

    private Dictionary<string, int> ParseServerPriceSettingsText()
    {
        var prices = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var lines = (ServerPriceSettingsText ?? string.Empty)
            .Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n')
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            var separatorIndex = line.IndexOf('=');
            if (separatorIndex <= 0 || separatorIndex == line.Length - 1)
            {
                throw new InvalidOperationException($"Linha inválida: {line}");
            }

            var key = line[..separatorIndex].Trim().ToLowerInvariant();
            var valueText = line[(separatorIndex + 1)..].Trim();
            if (string.IsNullOrWhiteSpace(key) || !int.TryParse(valueText, out var value) || value <= 0)
            {
                throw new InvalidOperationException($"Preço inválido: {line}");
            }

            prices[key] = value;
        }

        return prices;
    }

    private async Task RequestServerPriceSettingsAsync()
    {
        if (!_socketClient.IsConnected)
        {
            ServerPriceSettingsStatus = "Conecte-se ao servidor para carregar os preços.";
            return;
        }

        ServerPriceSettingsStatus = "Carregando preços do servidor...";
        await _socketClient.EmitAsync("request_price_settings", new { });
    }

    private async Task UpdateServerPriceSettingsAsync()
    {
        if (!_socketClient.IsConnected)
        {
            ServerPriceSettingsStatus = "Conecte-se ao servidor para salvar os preços.";
            return;
        }

        Dictionary<string, int> prices;
        try
        {
            prices = ParseServerPriceSettingsText();
        }
        catch (Exception ex)
        {
            ServerPriceSettingsStatus = ex.Message;
            return;
        }

        ServerPriceSettingsStatus = "Salvando preços do servidor...";
        await _socketClient.EmitAsync("update_price_settings", new
        {
            prices
        });
    }

    private void LoadLocalMessageContacts()
    {
        if (!_databaseInitialized)
        {
            return;
        }

        _messageContacts.Clear();
        foreach (var contact in _database.LoadMessageContacts())
        {
            _messageContacts.Add(contact);
        }
        if (SelectedMessageContact is null && _messageContacts.Count > 0)
        {
            SelectedMessageContact = _messageContacts[0];
        }
        RefreshMessageTargetOptions();
    }

    private void RefreshMessageTargetOptions()
    {
        var options = _messageContacts
            .Select(static item => item.PeerUser)
            .Concat(_incomingMessageRequests.Select(static item => item.PeerUser))
            .Concat(_outgoingMessageRequests.Select(static item => item.PeerUser))
            .Concat(NetworkNodes.Select(item => !string.IsNullOrWhiteSpace(item.Username) ? item.Username : item.Address))
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToList();

        _messageTargetOptions.Clear();
        foreach (var option in options)
        {
            _messageTargetOptions.Add(option);
        }

        var currentTarget = string.IsNullOrWhiteSpace(MessageTargetUser) ? null : MessageTargetUser.Trim();
        if (!string.IsNullOrWhiteSpace(currentTarget) &&
            !_messageTargetOptions.Any(option => string.Equals(option, currentTarget, StringComparison.OrdinalIgnoreCase)))
        {
            _messageTargetOptions.Insert(0, currentTarget);
        }
    }

    private void LoadConversationForPeer(string peerUser)
    {
        if (string.IsNullOrWhiteSpace(peerUser))
        {
            MessageConversationText = string.Empty;
            return;
        }

        var records = _database.LoadMessageRecords(peerUser);
        var lines = records.Select(item =>
        {
            var timestamp = item.Timestamp > 0
                ? DateTimeOffset.FromUnixTimeMilliseconds((long)(item.Timestamp * 1000)).ToLocalTime().ToString("g")
                : string.Empty;
            var author = string.Equals(item.Direction, "out", StringComparison.OrdinalIgnoreCase) ? "Você" : item.SenderUser;
            return $"{timestamp} | {author}: {item.Preview}";
        });
        MessageConversationText = string.Join(Environment.NewLine, lines);
    }

    private void SetMessageStatusState(string message, string tone = "info", bool pin = false)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        MessageStatus = message;
        switch ((tone ?? string.Empty).Trim().ToLowerInvariant())
        {
            case "error":
                MessageStatusTitle = "Falha em Mensagens";
                MessageStatusForeground = "#FFD7D7";
                MessageStatusBackground = "#4A1F1F";
                MessageStatusBorderBrush = "#C85A5A";
                break;
            case "success":
                MessageStatusTitle = "Mensagens";
                MessageStatusForeground = "#DDF5D4";
                MessageStatusBackground = "#1E3521";
                MessageStatusBorderBrush = "#6FB26A";
                break;
            case "warning":
                MessageStatusTitle = "Atenção em Mensagens";
                MessageStatusForeground = "#FFE8C2";
                MessageStatusBackground = "#4A3418";
                MessageStatusBorderBrush = "#D49B43";
                break;
            default:
                MessageStatusTitle = "Mensagens";
                MessageStatusForeground = "#EAEAEA";
                MessageStatusBackground = "#23303B";
                MessageStatusBorderBrush = "#5E829B";
                break;
        }

        _messageStatusPinnedUntil = pin
            ? DateTimeOffset.UtcNow.AddSeconds(12)
            : DateTimeOffset.MinValue;
    }

    private bool ShouldPreserveMessageStatus()
    {
        return DateTimeOffset.UtcNow < _messageStatusPinnedUntil;
    }

    private void ArmMessageOperationTimeout(string operationKind)
    {
        var version = Interlocked.Increment(ref _messageOperationVersion);
        _messageOperationKind = operationKind ?? string.Empty;
        _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(25)).ConfigureAwait(false);
            if (version != Volatile.Read(ref _messageOperationVersion))
            {
                return;
            }

            await RunOnUiAsync(() =>
            {
                var label = string.IsNullOrWhiteSpace(_messageOperationKind) ? "operação de mensagem" : _messageOperationKind;
                var pendingMessage = _pendingOutgoingMessage;
                SetMessageStatusState($"Timeout aguardando resposta para {label}.", "error", pin: true);
                if (string.Equals(_importantFlowKind, "message", StringComparison.OrdinalIgnoreCase))
                {
                    UpdateImportantFlowStatus($"Timeout aguardando resposta para {label}.");
                    MarkImportantFlowDone();
                }
                RestoreReservedLocalMessageBundleCredit(pendingMessage);
                RestoreReservedImcServerCredit(pendingMessage);
                _pendingOutgoingMessage = null;
            }).ConfigureAwait(false);
        });
    }

    private void CompleteMessageOperationTimeout()
    {
        Interlocked.Increment(ref _messageOperationVersion);
        _messageOperationKind = string.Empty;
    }

    private async Task RequestMessageStateAsync()
    {
        SetMessageStatusState("Mensagens foram removidas desta versão.", "warning", pin: true);
        await Task.CompletedTask;
    }

    private async Task RequestMessageContactAsync()
    {
        SetMessageStatusState("Mensagens foram removidas desta versão.", "warning", pin: true);
        await Task.CompletedTask;
    }

    private async Task AcceptMessageContactAsync()
    {
        SetMessageStatusState("Mensagens foram removidas desta versão.", "warning", pin: true);
        await Task.CompletedTask;
    }

    private async Task RejectMessageContactAsync()
    {
        SetMessageStatusState("Mensagens foram removidas desta versão.", "warning", pin: true);
        await Task.CompletedTask;
    }

    private async Task SendMessageAsync()
    {
        SetMessageStatusState("Mensagens foram removidas desta versão.", "warning", pin: true);
        await Task.CompletedTask;
    }

    private string BuildLastOutgoingMessageSnapshot(string targetUser)
    {
        if (!MessageIdentityMatches(_lastOutgoingMessageTarget, targetUser))
        {
            return string.Empty;
        }
        return _lastOutgoingMessageRaw;
    }

    private void ApplyMessageState(JsonElement payload)
    {
        var selectedContactPeer = SelectedMessageContact?.PeerUser ?? string.Empty;
        var selectedIncomingPeer = SelectedIncomingMessageRequest?.PeerUser ?? string.Empty;
        var selectedIncomingRequestId = SelectedIncomingMessageRequest?.RequestId ?? string.Empty;
        var selectedTarget = (MessageTargetUser ?? string.Empty).Trim();

        _messageLocalBundleRemaining = payload.TryGetProperty("pow_bundle_remaining", out var remainingProp) && remainingProp.ValueKind == JsonValueKind.Number
            ? remainingProp.GetInt32()
            : 0;
        _messageLocalBundleSize = payload.TryGetProperty("pow_bundle_size", out var sizeProp) && sizeProp.ValueKind == JsonValueKind.Number
            ? sizeProp.GetInt32()
            : 10;
        _messageRemoteBundleRemaining = payload.TryGetProperty("pow_remote_bundle_remaining", out var remoteRemainingProp) && remoteRemainingProp.ValueKind == JsonValueKind.Number
            ? remoteRemainingProp.GetInt32()
            : 0;
        _messageRemoteBundleSize = payload.TryGetProperty("pow_remote_bundle_size", out var remoteSizeProp) && remoteSizeProp.ValueKind == JsonValueKind.Number
            ? remoteSizeProp.GetInt32()
            : 5;
        UpdateMessageBundleStatusText();

        var contacts = new List<MessageContactInfo>();
        if (payload.TryGetProperty("contacts", out var contactsProp) && contactsProp.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in contactsProp.EnumerateArray())
            {
                contacts.Add(new MessageContactInfo
                {
                    PeerUser = GetJsonString(item, "peer_user"),
                    DisplayName = GetJsonString(item, "display_name"),
                    ApprovedAt = item.TryGetProperty("approved_at", out var approvedProp) && approvedProp.ValueKind == JsonValueKind.Number ? approvedProp.GetDouble() : 0,
                    LastMessageAt = item.TryGetProperty("last_message_at", out var lastProp) && lastProp.ValueKind == JsonValueKind.Number ? lastProp.GetDouble() : 0,
                    Initiator = GetJsonString(item, "initiator")
                });
            }
        }

        _database.ReplaceMessageContacts(contacts);
        _messageContacts.Clear();
        foreach (var contact in contacts)
        {
            _messageContacts.Add(contact);
        }

        _incomingMessageRequests.Clear();
        if (payload.TryGetProperty("incoming_requests", out var incomingProp) && incomingProp.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in incomingProp.EnumerateArray())
            {
                _incomingMessageRequests.Add(new MessageRequestInfo
                {
                    RequestId = GetJsonString(item, "request_id"),
                    PeerUser = GetJsonString(item, "peer_user"),
                    DisplayName = GetJsonString(item, "display_name"),
                    Sender = GetJsonString(item, "sender"),
                    Receiver = GetJsonString(item, "receiver"),
                    CreatedAt = item.TryGetProperty("created_at", out var createdProp) && createdProp.ValueKind == JsonValueKind.Number ? createdProp.GetDouble() : 0
                });
            }
        }

        _outgoingMessageRequests.Clear();
        if (payload.TryGetProperty("outgoing_requests", out var outgoingProp) && outgoingProp.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in outgoingProp.EnumerateArray())
            {
                _outgoingMessageRequests.Add(new MessageRequestInfo
                {
                    RequestId = GetJsonString(item, "request_id"),
                    PeerUser = GetJsonString(item, "peer_user"),
                    DisplayName = GetJsonString(item, "display_name"),
                    Sender = GetJsonString(item, "sender"),
                    Receiver = GetJsonString(item, "receiver"),
                    CreatedAt = item.TryGetProperty("created_at", out var createdProp) && createdProp.ValueKind == JsonValueKind.Number ? createdProp.GetDouble() : 0
                });
            }
        }

        SelectedIncomingMessageRequest = _incomingMessageRequests.FirstOrDefault(item =>
            (!string.IsNullOrWhiteSpace(selectedIncomingRequestId) && string.Equals(item.RequestId, selectedIncomingRequestId, StringComparison.OrdinalIgnoreCase)) ||
            (!string.IsNullOrWhiteSpace(selectedIncomingPeer) && MessageIdentityMatches(item.PeerUser, selectedIncomingPeer)));

        SelectedMessageContact = _messageContacts.FirstOrDefault(item =>
            (!string.IsNullOrWhiteSpace(selectedContactPeer) && MessageIdentityMatches(item.PeerUser, selectedContactPeer)) ||
            (!string.IsNullOrWhiteSpace(selectedTarget) && MessageIdentityMatches(item.PeerUser, selectedTarget)));

        if (SelectedIncomingMessageRequest is null &&
            SelectedMessageContact is null &&
            !string.IsNullOrWhiteSpace(selectedTarget))
        {
            MessageTargetUser = ResolvePreferredMessageTarget(selectedTarget);
        }

        if (SelectedMessageContact is null && _messageContacts.Count > 0)
        {
            SelectedMessageContact = _messageContacts[0];
        }
        RefreshMessageTargetOptions();
    }

    private void UpdateMessageBundleStatusText()
    {
        MessageBundleStatus = "Mensagens foram removidas desta versão.";
    }

    private void AdjustImcServerBalanceDisplay(int delta)
    {
        _imcHpsServerBalanceValue = Math.Max(0, _imcHpsServerBalanceValue + delta);
        ImcHpsSummary = "IMC-HPS foi removido desta versão.";
        UpdateMessageBundleStatusText();
    }

    private Task RefreshImcHpsAsync()
    {
        ImcHpsStatus = "IMC-HPS foi removido desta versão.";
        ImcHpsSummary = "IMC-HPS foi removido desta versão.";
        UpdateMessageBundleStatusText();
        return Task.CompletedTask;
    }

    private bool TryReserveLocalMessageBundleCredit(string actionType)
    {
        if (!string.Equals(actionType, "message_local", StringComparison.OrdinalIgnoreCase) || _messageLocalBundleRemaining <= 0)
        {
            return false;
        }

        _messageLocalBundleRemaining--;
        UpdateMessageBundleStatusText();
        return true;
    }

    private void RestoreReservedLocalMessageBundleCredit(PendingOutgoingMessage? pendingMessage)
    {
        if (pendingMessage is null || !pendingMessage.UsesLocalBundleCredit)
        {
            return;
        }

        _messageLocalBundleRemaining++;
        UpdateMessageBundleStatusText();
    }

    private void RestoreReservedImcServerCredit(PendingOutgoingMessage? pendingMessage)
    {
        if (pendingMessage is null || !pendingMessage.UsesImcServerCredit)
        {
            return;
        }

        AdjustImcServerBalanceDisplay(1);
    }

    private string ResolvePreferredMessageTarget(string targetUser)
    {
        targetUser = (targetUser ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(targetUser) || IsLikelyRemoteMessageTarget(targetUser))
        {
            return targetUser;
        }

        if (SelectedMessageContact is not null &&
            TryParseRemoteMessageTarget(SelectedMessageContact.PeerUser, out _, out var selectedRemoteUser) &&
            string.Equals(selectedRemoteUser, targetUser, StringComparison.OrdinalIgnoreCase))
        {
            return SelectedMessageContact.PeerUser;
        }
        if (SelectedIncomingMessageRequest is not null &&
            TryParseRemoteMessageTarget(SelectedIncomingMessageRequest.PeerUser, out _, out var incomingRemoteUser) &&
            string.Equals(incomingRemoteUser, targetUser, StringComparison.OrdinalIgnoreCase))
        {
            return SelectedIncomingMessageRequest.PeerUser;
        }
        var remoteMatches = _messageContacts
            .Select(static item => item.PeerUser)
            .Concat(_incomingMessageRequests.Select(static item => item.PeerUser))
            .Concat(_outgoingMessageRequests.Select(static item => item.PeerUser))
            .Where(TryResolveRemoteUsernameMatch)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return remoteMatches.Count == 1 ? remoteMatches[0] : targetUser;

        bool TryResolveRemoteUsernameMatch(string peerUser)
        {
            return TryParseRemoteMessageTarget(peerUser, out _, out var remoteUser) &&
                   string.Equals(remoteUser, targetUser, StringComparison.OrdinalIgnoreCase);
        }
    }

    private void SaveIncomingOrOutgoingMessage(string peerUser, string senderUser, string direction, string fileName, string rawMessage, string preview, double timestamp)
    {
        var filePath = _contentService.SaveMessageFileToStorage(User, peerUser, fileName, Encoding.UTF8.GetBytes(rawMessage));
        var messageId = $"{peerUser}:{fileName}";
        _database.SaveMessageRecord(messageId, peerUser, senderUser, direction, fileName, filePath, preview, timestamp);
        if (MessageIdentityMatches(MessageTargetUser, peerUser))
        {
            LoadConversationForPeer(peerUser);
        }
    }

    private static double NormalizeMessageTimestamp(double timestamp)
    {
        if (timestamp <= 0 || double.IsNaN(timestamp) || double.IsInfinity(timestamp))
        {
            return 0;
        }

        if (timestamp >= 1000000000000d)
        {
            return timestamp / 1000d;
        }

        return timestamp;
    }

    private void UpdateMessageComposeSuggestions()
    {
        _messageComposeSuggestions.Clear();
        var token = GetCurrentMessageToken(MessageComposeText);
        if (string.IsNullOrWhiteSpace(token))
        {
            MessageComposeHelp = "Use @hash para anexos e #usuario ou #servidor@usuario para menções.";
            return;
        }

        if (token.StartsWith("@", StringComparison.Ordinal))
        {
            var needle = token[1..].Trim();
            var hashes = new[]
            {
                UploadHash,
                SelectedSearchResult?.ContentHash ?? string.Empty,
                _lastContentHash
            }
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(value => value.StartsWith(needle, StringComparison.OrdinalIgnoreCase))
            .Take(6);

            foreach (var hash in hashes)
            {
                _messageComposeSuggestions.Add("@" + hash);
            }
            MessageComposeHelp = _messageComposeSuggestions.Count > 0
                ? "Anexo detectado. Clique em um hash para inserir @<hash>."
                : "Use @<hash> para anexar um arquivo público da rede HPS.";
            return;
        }

        if (token.StartsWith("#", StringComparison.Ordinal))
        {
            var needle = token[1..].Trim();
            var candidates = new List<string>();
            candidates.AddRange(_messageContacts.Select(static item => item.PeerUser));
            candidates.AddRange(NetworkNodes.Select(static item => item.Username));
            candidates.AddRange(_incomingMessageRequests.Select(static item => item.PeerUser));
            var suggestions = candidates
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(value => value.StartsWith(needle, StringComparison.OrdinalIgnoreCase))
                .Take(8);

            foreach (var suggestion in suggestions)
            {
                _messageComposeSuggestions.Add("#" + suggestion);
            }
            MessageComposeHelp = _messageComposeSuggestions.Count > 0
                ? "Menção detectada. Clique em um usuário para inserir a menção."
                : "Use #usuario para o mesmo servidor ou #servidor@usuario para outro servidor.";
            return;
        }

        MessageComposeHelp = "Use @hash para anexos e #usuario ou #servidor@usuario para menções.";
    }

    private static string GetCurrentMessageToken(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        var tokens = text.Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0)
        {
            return string.Empty;
        }

        var last = tokens[^1].Trim();
        return last.StartsWith("@", StringComparison.Ordinal) || last.StartsWith("#", StringComparison.Ordinal)
            ? last
            : string.Empty;
    }

    private void ApplyMessageTokenSuggestion(object? parameter)
    {
        var suggestion = (parameter as string)?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(suggestion))
        {
            return;
        }

        var text = MessageComposeText ?? string.Empty;
        var token = GetCurrentMessageToken(text);
        if (string.IsNullOrWhiteSpace(token))
        {
            MessageComposeText = string.IsNullOrWhiteSpace(text) ? suggestion + " " : text.TrimEnd() + " " + suggestion + " ";
            return;
        }

        var index = text.LastIndexOf(token, StringComparison.Ordinal);
        if (index < 0)
        {
            MessageComposeText = text.TrimEnd() + " " + suggestion + " ";
            return;
        }

        MessageComposeText = text[..index] + suggestion + " ";
    }

    private static bool IsLikelyMessageServerSegment(string value)
    {
        value = (value ?? string.Empty).Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.Contains('.') || value.Contains(':') || value.Contains('/') || value.Contains("localhost", StringComparison.Ordinal);
    }

    private static string ExtractComparableMessageUser(string value)
    {
        value = (value ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(value) || !value.Contains('@'))
        {
            return value.ToLowerInvariant();
        }

        var parts = value.Split('@', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
        {
            return value.ToLowerInvariant();
        }

        if (IsLikelyMessageServerSegment(parts[0]) && !IsLikelyMessageServerSegment(parts[1]))
        {
            return parts[1].ToLowerInvariant();
        }

        if (!IsLikelyMessageServerSegment(parts[0]) && IsLikelyMessageServerSegment(parts[1]))
        {
            return parts[0].ToLowerInvariant();
        }

        return value.ToLowerInvariant();
    }

    private static bool MessageIdentityMatches(string parsedValue, string expectedValue)
    {
        var parsed = (parsedValue ?? string.Empty).Trim();
        var expected = (expectedValue ?? string.Empty).Trim();
        if (string.Equals(parsed, expected, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return string.Equals(
            ExtractComparableMessageUser(parsed),
            ExtractComparableMessageUser(expected),
            StringComparison.OrdinalIgnoreCase);
    }

    private static string ResolveMessageActionType(string targetUser)
    {
        return IsLikelyRemoteMessageTarget(targetUser) ? "message_remote" : "message_local";
    }

    private static bool IsLikelyRemoteMessageTarget(string targetUser)
    {
        var value = (targetUser ?? string.Empty).Trim();
        if (!value.Contains('@'))
        {
            return false;
        }

        var parts = value.Split('@', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
        {
            return false;
        }

        return (IsLikelyMessageServerSegment(parts[0]) && !string.IsNullOrWhiteSpace(parts[1])) ||
               (IsLikelyMessageServerSegment(parts[1]) && !string.IsNullOrWhiteSpace(parts[0]));
    }

    private static bool TryParseRemoteMessageTarget(string targetUser, out string serverAddress, out string username)
    {
        serverAddress = string.Empty;
        username = string.Empty;
        var value = (targetUser ?? string.Empty).Trim();
        if (!IsLikelyRemoteMessageTarget(value))
        {
            return false;
        }

        var parts = value.Split('@', 2, StringSplitOptions.TrimEntries);
        if (parts.Length != 2)
        {
            return false;
        }

        if (IsLikelyMessageServerSegment(parts[0]))
        {
            serverAddress = parts[0];
            username = parts[1];
        }
        else
        {
            serverAddress = parts[1];
            username = parts[0];
        }

        return !string.IsNullOrWhiteSpace(serverAddress) && !string.IsNullOrWhiteSpace(username);
    }

    private async Task<int> ResolveQuotedMessageCostAsync(string targetUser)
    {
        if (!IsLikelyRemoteMessageTarget(targetUser) || !TryParseRemoteMessageTarget(targetUser, out var remoteServer, out _))
        {
            return GetHpsPowSkipCost("message_local");
        }

        var localCost = GetHpsPowSkipCost("message_local");
        if (localCost <= 0)
        {
            localCost = 1;
        }

        try
        {
            var report = await _serverApiClient.FetchJsonPathAsync(remoteServer, false, "/economy_report");
            if (report is JsonElement json &&
                json.ValueKind == JsonValueKind.Object &&
                json.TryGetProperty("payload", out var payload) &&
                payload.ValueKind == JsonValueKind.Object &&
                payload.TryGetProperty("pow_costs", out var powCosts) &&
                powCosts.ValueKind == JsonValueKind.Object)
            {
                var remoteCost = 0;
                if (powCosts.TryGetProperty("message_local", out var remoteProp))
                {
                    remoteCost = remoteProp.ValueKind == JsonValueKind.Number ? remoteProp.GetInt32() : int.TryParse(remoteProp.GetString(), out var parsed) ? parsed : 0;
                }
                if (remoteCost <= 0 && powCosts.TryGetProperty("message_remote", out var remoteRemoteProp))
                {
                    remoteCost = remoteRemoteProp.ValueKind == JsonValueKind.Number ? remoteRemoteProp.GetInt32() : int.TryParse(remoteRemoteProp.GetString(), out var parsed) ? parsed : 0;
                    if (remoteCost > localCost)
                    {
                        remoteCost -= localCost;
                    }
                }
                if (remoteCost <= 0)
                {
                    remoteCost = 1;
                }
                var total = Math.Max(1, localCost) + Math.Max(1, remoteCost);
                _hpsPowSkipCosts["message_remote"] = total;
                return total;
            }
        }
        catch
        {
            // Keep fallback cost.
        }

        var fallback = GetHpsPowSkipCost("message_remote");
        return fallback > 0 ? fallback : Math.Max(2, localCost + 1);
    }

    private bool TryParseSignedMessage(string rawMessage, out string fromUser, out string toUser, out double timestamp, out string preview, out string signature, out string signedText)
    {
        fromUser = string.Empty;
        toUser = string.Empty;
        timestamp = 0;
        preview = string.Empty;
        signature = string.Empty;
        signedText = string.Empty;

        var normalized = rawMessage.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        var lines = normalized.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length < 7 || !string.Equals(lines[0].Trim(), "# HSYST P2P SERVICE", StringComparison.Ordinal))
        {
            return false;
        }

        var signedLines = new List<string>();
        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("# FROM:", StringComparison.Ordinal))
            {
                fromUser = trimmed["# FROM:".Length..].Trim();
            }
            else if (trimmed.StartsWith("# TO:", StringComparison.Ordinal))
            {
                toUser = trimmed["# TO:".Length..].Trim();
            }
            else if (trimmed.StartsWith("# TIMESTAMP:", StringComparison.Ordinal))
            {
                _ = double.TryParse(trimmed["# TIMESTAMP:".Length..].Trim(), NumberStyles.Any, CultureInfo.InvariantCulture, out timestamp);
                timestamp = NormalizeMessageTimestamp(timestamp);
            }
            else if (trimmed.StartsWith("# CONTENT_BASE64:", StringComparison.Ordinal))
            {
                var encoded = trimmed["# CONTENT_BASE64:".Length..].Trim();
                preview = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            }
            else if (trimmed.StartsWith("# SIGNATURE:", StringComparison.Ordinal))
            {
                signature = trimmed["# SIGNATURE:".Length..].Trim();
                continue;
            }
            signedLines.Add(line);
        }

        signedText = string.Join("\n", signedLines) + "\n";
        return !string.IsNullOrWhiteSpace(fromUser) &&
               !string.IsNullOrWhiteSpace(toUser) &&
               !string.IsNullOrWhiteSpace(signature);
    }

    private bool TryBuildSpendPayment(string actionType, int cost, out object? payment)
    {
        payment = null;
        if (_privateKey is null || cost <= 0)
        {
            return false;
        }

        var issuer = ServerAddress ?? string.Empty;
        var (voucherIds, total) = SelectHpsVouchersForCost(cost, issuer);
        if (total < cost || voucherIds.Count == 0)
        {
            return false;
        }

        var details = new Dictionary<string, string>
        {
            { "ACTION_TYPE", actionType },
            { "COST", cost.ToString() },
            { "VOUCHERS", JsonSerializer.Serialize(voucherIds) }
        };
        var contractText = _contentService.BuildContractTemplate("spend_hps", details);
        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);
        var contractB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract));
        payment = new
        {
            voucher_ids = voucherIds,
            contract_content = contractB64
        };
        return true;
    }

    private PhpsDebtInfo? ParsePhpsDebt(JsonElement element)
    {
        try
        {
            return new PhpsDebtInfo
            {
                DebtId = element.TryGetProperty("debt_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty,
                Reason = element.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() ?? string.Empty : string.Empty,
                TargetType = element.TryGetProperty("target_type", out var typeProp) ? typeProp.GetString() ?? string.Empty : string.Empty,
                TargetId = element.TryGetProperty("target_id", out var targetProp) ? targetProp.GetString() ?? string.Empty : string.Empty,
                Principal = element.TryGetProperty("principal", out var principalProp) ? principalProp.GetInt32() : 0,
                PayoutTotal = element.TryGetProperty("payout_total", out var payoutProp) ? payoutProp.GetInt32() : 0,
                ReservedAmount = element.TryGetProperty("reserved_amount", out var reservedProp) ? reservedProp.GetInt32() : 0,
                CreditorUsername = element.TryGetProperty("creditor_username", out var creditorProp) ? creditorProp.GetString() ?? string.Empty : string.Empty,
                Status = element.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? string.Empty : string.Empty,
                CreatedAt = element.TryGetProperty("created_at", out var createdProp) ? createdProp.GetDouble() : 0
            };
        }
        catch
        {
            return null;
        }
    }

    private void ApplyPhpsMarketPayload(JsonElement payload)
    {
        if (payload.TryGetProperty("custody_balance", out var balanceProp))
        {
            CustodyDebtSummary = $"Custódia: {balanceProp.GetDouble():0.##} HPS";
        }

        _phpsMarketItems.Clear();
        _myPhpsDebts.Clear();

        if (payload.TryGetProperty("items", out var itemsProp) && itemsProp.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in itemsProp.EnumerateArray())
            {
                var parsed = ParsePhpsDebt(item);
                if (parsed is not null)
                {
                    _phpsMarketItems.Add(parsed);
                }
            }
        }

        if (payload.TryGetProperty("my_items", out var mineProp) && mineProp.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in mineProp.EnumerateArray())
            {
                var parsed = ParsePhpsDebt(item);
                if (parsed is not null)
                {
                    _myPhpsDebts.Add(parsed);
                }
            }
        }

        if (_phpsMarketItems.Count == 0)
        {
            PhpsMarketStatus = "Nenhum contrato pHPS encontrado.";
        }
        else
        {
            PhpsMarketStatus = $"Mercado pHPS carregado: {_phpsMarketItems.Count} contrato(s).";
        }
    }

    private async Task RefreshPhpsMarketAsync()
    {
        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            PhpsMarketStatus = "Conecte-se à rede primeiro.";
            return;
        }

        PhpsMarketStatus = "Atualizando mercado pHPS...";
        await _socketClient.EmitAsync("get_phps_market", new { });
    }

    private bool TryGetSelectedIssuerExceptionTarget(out string targetType, out string targetId)
    {
        targetType = string.Empty;
        targetId = string.Empty;
        if (SelectedContract is null || !string.Equals(SelectedContract.ActionType, "check_for_files_except", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        targetType = ExtractContractDetail(SelectedContract.ContractContent, "TARGET_TYPE");
        targetId = ExtractContractDetail(SelectedContract.ContractContent, "TARGET_ID");
        if (string.Equals(targetType, "dns", StringComparison.OrdinalIgnoreCase))
        {
            targetType = "domain";
        }
        return !string.IsNullOrWhiteSpace(targetType) && !string.IsNullOrWhiteSpace(targetId);
    }

    private async Task RequestIssuerRecheckAsync()
    {
        if (!IsLoggedIn || !_socketClient.IsConnected || _privateKey is null || _owner is null)
        {
            IssuerRecheckStatus = "Conecte-se à rede primeiro.";
            return;
        }
        if (!TryGetSelectedIssuerExceptionTarget(out var targetType, out var targetId))
        {
            IssuerRecheckStatus = "Selecione um contrato check_for_files_except.";
            return;
        }

        var payment = await PrepareHpsPaymentAsync("issuer_recheck", null);
        if (payment is null)
        {
            IssuerRecheckStatus = "Revogação cancelada ou saldo insuficiente.";
            return;
        }

        var details = new Dictionary<string, string>
        {
            { "TARGET_TYPE", targetType },
            { "TARGET_ID", targetId },
            { "COST", "2" }
        };
        var contractText = _contentService.BuildContractTemplate("issuer_recheck", details);
        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);
        var contractB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract));
        IssuerRecheckStatus = "Solicitando nova checagem de emissão...";
        await _socketClient.EmitAsync("request_issuer_recheck", new
        {
            target_type = targetType,
            target_id = targetId,
            contract_content = contractB64,
            hps_payment = payment.Payload
        });
    }

    private async Task FundSelectedPhpsDebtAsync()
    {
        if (!IsLoggedIn || !_socketClient.IsConnected || _privateKey is null || _owner is null || SelectedPhpsDebt is null)
        {
            PhpsMarketStatus = "Selecione uma dívida pHPS.";
            return;
        }
        if (!string.Equals(SelectedPhpsDebt.Status, "open", StringComparison.OrdinalIgnoreCase))
        {
            PhpsMarketStatus = "Essa dívida não está mais aberta.";
            return;
        }

        var selection = await PrepareVoucherSelectionAsync(
            SelectedPhpsDebt.Principal,
            "Assumir dívida da custódia",
            $"Você vai pagar {SelectedPhpsDebt.Principal} HPS para assumir a dívida {SelectedPhpsDebt.DebtId}.\n" +
            $"Retorno esperado: {SelectedPhpsDebt.PayoutTotal} HPS.\n" +
            $"Reservado até agora: {SelectedPhpsDebt.ReservedAmount} HPS.");
        if (selection is null)
        {
            PhpsMarketStatus = "Operação cancelada ou saldo insuficiente.";
            return;
        }

        var details = new Dictionary<string, string>
        {
            { "DEBT_ID", SelectedPhpsDebt.DebtId },
            { "AMOUNT", SelectedPhpsDebt.Principal.ToString(CultureInfo.InvariantCulture) },
            { "VOUCHERS", JsonSerializer.Serialize(selection.VoucherIds) }
        };
        var contractText = _contentService.BuildContractTemplate("phps_fund", details);
        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);
        var contractB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract));
        PhpsMarketStatus = "Enviando aporte para a custódia...";
        await _socketClient.EmitAsync("fund_phps_debt", new
        {
            debt_id = SelectedPhpsDebt.DebtId,
            voucher_ids = selection.VoucherIds,
            contract_content = contractB64
        });
    }

    private async Task ProcessIssuerVerificationJobAsync(JsonElement payload)
    {
        if (_privateKey is null || !_isMinerMode || !_socketClient.IsConnected)
        {
            return;
        }

        var jobId = payload.TryGetProperty("job_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
        var targetType = payload.TryGetProperty("target_type", out var typeProp) ? typeProp.GetString() ?? string.Empty : string.Empty;
        var targetId = payload.TryGetProperty("target_id", out var targetProp) ? targetProp.GetString() ?? string.Empty : string.Empty;
        var issuerServer = payload.TryGetProperty("issuer_server", out var issuerProp) ? issuerProp.GetString() ?? string.Empty : string.Empty;
        var issuerPublicKey = payload.TryGetProperty("issuer_public_key", out var keyProp) ? keyProp.GetString() ?? string.Empty : string.Empty;
        var issuerContractId = payload.TryGetProperty("issuer_contract_id", out var contractProp) ? contractProp.GetString() ?? string.Empty : string.Empty;
        if (string.IsNullOrWhiteSpace(jobId) || string.IsNullOrWhiteSpace(targetType) || string.IsNullOrWhiteSpace(targetId) || string.IsNullOrWhiteSpace(issuerServer))
        {
            return;
        }

        var reportResult = "failed";
        var detail = "issuer_check_failed";
        try
        {
            var useSsl = issuerServer.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            var info = await _serverApiClient.FetchServerInfoAsync(issuerServer, useSsl);
            if (info is null)
            {
                reportResult = "timeout";
                detail = "server_info_timeout";
            }
            else
            {
                var remoteKey = info.Value.TryGetProperty("public_key", out var remoteKeyProp) ? remoteKeyProp.GetString() ?? string.Empty : string.Empty;
                if (!string.IsNullOrWhiteSpace(issuerPublicKey) &&
                    !string.Equals(CryptoUtils.NormalizePublicKey(remoteKey), CryptoUtils.NormalizePublicKey(issuerPublicKey), StringComparison.OrdinalIgnoreCase))
                {
                    detail = "issuer_public_key_mismatch";
                }
                else
                {
                    var remoteContract = await _serverApiClient.FetchContractAsync(issuerServer, useSsl, issuerContractId);
                    if (string.IsNullOrWhiteSpace(remoteContract))
                    {
                        reportResult = "timeout";
                        detail = "issuer_contract_timeout";
                    }
                    else
                    {
                        var action = ExtractContractDetail(remoteContract, "ACTION");
                        var contractTargetType = ExtractContractDetail(remoteContract, "TARGET_TYPE");
                        var contractTargetId = ExtractContractDetail(remoteContract, "TARGET_ID");
                        var signature = ExtractSignedContractSignature(remoteContract);
                        var expectedAction = string.Equals(targetType, "domain", StringComparison.OrdinalIgnoreCase) ? "dns_issuer_attest" : "content_issuer_attest";
                        if (!string.Equals(action, expectedAction, StringComparison.OrdinalIgnoreCase) ||
                            !string.Equals(contractTargetType, targetType, StringComparison.OrdinalIgnoreCase) ||
                            !string.Equals(contractTargetId, targetId, StringComparison.OrdinalIgnoreCase))
                        {
                            detail = "issuer_contract_target_mismatch";
                        }
                        var contractPublicKey = ExtractContractDetail(remoteContract, "PUBLIC_KEY");
                        if (string.IsNullOrWhiteSpace(contractPublicKey))
                        {
                            contractPublicKey = issuerPublicKey;
                        }
                        if (!TryVerifyContractSignature(contractPublicKey, GetSignedContractText(remoteContract), signature))
                        {
                            detail = "issuer_contract_signature_invalid";
                        }
                        else
                        {
                            var path = string.Equals(targetType, "domain", StringComparison.OrdinalIgnoreCase)
                                ? $"/sync/dns?domain={Uri.EscapeDataString(targetId)}"
                                : $"/sync/content?content_hash={Uri.EscapeDataString(targetId)}";
                            var metadata = await _serverApiClient.FetchJsonPathAsync(issuerServer, useSsl, path);
                            if (metadata is null)
                            {
                                reportResult = "timeout";
                                detail = "issuer_metadata_timeout";
                            }
                            else if (!MetadataContainsTarget(metadata.Value, targetType, targetId))
                            {
                                detail = "issuer_metadata_missing";
                            }
                            else
                            {
                                reportResult = "confirmed";
                                detail = "issuer_confirmed";
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            reportResult = "failed";
            detail = ex.Message;
        }

        var details = new Dictionary<string, string>
        {
            { "JOB_ID", jobId },
            { "TARGET_TYPE", targetType },
            { "TARGET_ID", targetId },
            { "ISSUER_SERVER", issuerServer },
            { "ISSUER_CONTRACT_ID", issuerContractId },
            { "RESULT_STATUS", reportResult },
            { "DETAIL", detail }
        };
        var contractText = _contentService.BuildContractTemplate("issuer_verification_report", details);
        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);
        var contractB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract));
        AppendPowLog($"Job de checagem do emissor {jobId}: {reportResult} ({detail}).");
        await _socketClient.EmitAsync("submit_issuer_verification_report", new
        {
            job_id = jobId,
            contract_content = contractB64
        });
    }

    private static bool MetadataContainsTarget(JsonElement payload, string targetType, string targetId)
    {
        if (!payload.TryGetProperty("items", out var itemsProp) || itemsProp.ValueKind != JsonValueKind.Array)
        {
            return false;
        }
        var keyName = string.Equals(targetType, "domain", StringComparison.OrdinalIgnoreCase) ? "domain" : "content_hash";
        foreach (var item in itemsProp.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
            {
                continue;
            }
            if (item.TryGetProperty(keyName, out var valueProp) &&
                string.Equals(valueProp.GetString(), targetId, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static InventoryItem? BuildInventoryItemFromPayload(JsonElement itemElem, string fallbackOwner, string source)
    {
        if (itemElem.ValueKind != JsonValueKind.Object)
        {
            return null;
        }
        var contentHash = itemElem.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty;
        if (string.IsNullOrWhiteSpace(contentHash))
        {
            return null;
        }
        var title = itemElem.TryGetProperty("title", out var titleProp) ? titleProp.GetString() ?? string.Empty : string.Empty;
        var description = itemElem.TryGetProperty("description", out var descProp) ? descProp.GetString() ?? string.Empty : string.Empty;
        var mimeType = itemElem.TryGetProperty("mime_type", out var mimeProp) ? mimeProp.GetString() ?? string.Empty : string.Empty;
        var size = itemElem.TryGetProperty("size", out var sizeProp) ? sizeProp.GetInt64() : 0;
        var owner = itemElem.TryGetProperty("owner", out var ownerProp) ? ownerProp.GetString() ?? string.Empty : string.Empty;
        if (string.IsNullOrWhiteSpace(owner))
        {
            owner = fallbackOwner;
        }
        return new InventoryItem
        {
            ContentHash = contentHash,
            Title = title,
            Description = description,
            MimeType = mimeType,
            Size = size,
            Owner = owner,
            Source = source,
            IsPublic = true
        };
    }

    private void ReserveLocalVouchers(IEnumerable<string> voucherIds)
    {
        var ids = voucherIds.ToList();
        if (ids.Count == 0)
        {
            return;
        }
        _database.UpdateVoucherStatus(ids, "reserved", false);
        foreach (var voucher in Vouchers.Where(v => ids.Contains(v.VoucherId)))
        {
            voucher.Status = "reserved";
            voucher.DisplayStatus = voucher.IsUsable ? "reserved" : "unusable - Inutilizavel";
        }
        UpdateHpsBalance();
        PersistEncryptedDatabaseSnapshotSafe();
    }

    private void ReleaseLocalVouchers(IEnumerable<string> voucherIds)
    {
        var ids = voucherIds.ToList();
        if (ids.Count == 0)
        {
            return;
        }
        _database.UpdateVoucherStatus(ids, "active", false);
        foreach (var voucher in Vouchers.Where(v => ids.Contains(v.VoucherId)))
        {
            voucher.Status = "active";
            voucher.DisplayStatus = voucher.IsUsable ? "active" : "unusable - Inutilizavel";
        }
        UpdateHpsBalance();
        PersistEncryptedDatabaseSnapshotSafe();
    }

    private void BlockLocalSpendVouchers(IEnumerable<string> voucherIds)
    {
        foreach (var id in voucherIds.Where(id => !string.IsNullOrWhiteSpace(id)))
        {
            _locallyBlockedSpendVoucherIds.Add(id);
        }
        UpdateHpsBalance();
    }

    private void UnblockLocalSpendVouchers(IEnumerable<string> voucherIds)
    {
        foreach (var id in voucherIds.Where(id => !string.IsNullOrWhiteSpace(id)))
        {
            _locallyBlockedSpendVoucherIds.Remove(id);
        }
        UpdateHpsBalance();
    }

    private void ResolvePendingHpsPaymentsAfterWalletSync()
    {
        if (_pendingHpsPaymentsAwaitingWalletSync.Count == 0)
        {
            return;
        }

        var resolved = _pendingHpsPaymentsAwaitingWalletSync.ToList();
        foreach (var actionType in resolved)
        {
            if (_pendingHpsPayments.TryGetValue(actionType, out var voucherIds))
            {
                UnblockLocalSpendVouchers(voucherIds);
                _pendingHpsPayments.Remove(actionType);
            }
            _pendingHpsPaymentsAwaitingWalletSync.Remove(actionType);
        }
        UpdateAutomaticStateSyncLoop();
    }

    private bool HasAutomaticStateSyncWork()
    {
        return _socketClient.IsConnected &&
               IsLoggedIn &&
               (_pendingHpsPaymentsAwaitingWalletSync.Count > 0 ||
                !string.IsNullOrWhiteSpace(_pendingExchangeTransferId) ||
                _pendingMinerTransfers.Count > 0);
    }

    private void UpdateAutomaticStateSyncLoop()
    {
        if (!HasAutomaticStateSyncWork())
        {
            _pendingWalletRefreshCts?.Cancel();
            return;
        }

        StartPendingWalletRefreshLoop();
    }

    private void StartPendingWalletRefreshLoop()
    {
        if (!HasAutomaticStateSyncWork())
        {
            return;
        }
        if (_pendingWalletRefreshCts is not null && !_pendingWalletRefreshCts.IsCancellationRequested)
        {
            return;
        }

        _pendingWalletRefreshCts = new CancellationTokenSource();
        var token = _pendingWalletRefreshCts.Token;
        _ = Task.Run(async () =>
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    if (!HasAutomaticStateSyncWork())
                    {
                        break;
                    }

                    var needsWallet = _pendingHpsPaymentsAwaitingWalletSync.Count > 0 || !string.IsNullOrWhiteSpace(_pendingExchangeVoucherId);
                    var needsPendingTransfers = !string.IsNullOrWhiteSpace(_pendingExchangeTransferId);
                    var needsMinerPendingTransfers = needsPendingTransfers || _pendingMinerTransfers.Count > 0;

                    QueueAutomaticStateRefresh(
                        wallet: needsWallet,
                        pendingTransfers: needsPendingTransfers,
                        minerPendingTransfers: needsMinerPendingTransfers);

                    await Task.Delay(1200, token).ConfigureAwait(false);
                }
            }
            catch
            {
            }
            finally
            {
                _pendingWalletRefreshCts?.Dispose();
                _pendingWalletRefreshCts = null;
                if (HasAutomaticStateSyncWork())
                {
                    StartPendingWalletRefreshLoop();
                }
            }
        }, token);
    }

    private void RegisterSocketHandlers()
    {
        _socketClient.OnAsync("server_auth_challenge", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (!payload.TryGetProperty("challenge", out var challengeProp) ||
                !payload.TryGetProperty("server_public_key", out var serverKeyProp) ||
                !payload.TryGetProperty("signature", out var signatureProp))
            {
                LoginStatus = "Falha na autenticação do servidor: dados incompletos";
                return;
            }

            var challenge = challengeProp.GetString() ?? string.Empty;
            var serverPublicKeyB64 = serverKeyProp.GetString() ?? string.Empty;
            var signatureB64 = signatureProp.GetString() ?? string.Empty;

            if (string.IsNullOrWhiteSpace(challenge) ||
                string.IsNullOrWhiteSpace(serverPublicKeyB64) ||
                string.IsNullOrWhiteSpace(signatureB64))
            {
                LoginStatus = "Falha na autenticação do servidor: dados incompletos";
                return;
            }

            try
            {
                var serverPemBytes = Convert.FromBase64String(serverPublicKeyB64);
                var serverPem = Encoding.UTF8.GetString(serverPemBytes);
                using var serverKey = CryptoUtils.LoadPublicKey(serverPem)
                    ?? CryptoUtils.LoadPublicKey(serverPublicKeyB64);
                if (serverKey is null)
                {
                    LoginStatus = "Falha na autenticação do servidor: chave inválida";
                    return;
                }

                var signatureBytes = Convert.FromBase64String(signatureB64);
                var ok = CryptoUtils.VerifySignature(serverKey, challenge, signatureBytes);
                if (!ok)
                {
                    ok = CryptoUtils.VerifySignaturePssHashLen(serverKey, challenge, signatureBytes);
                }
                if (!ok)
                {
                    ok = CryptoUtils.VerifySignaturePssMax(serverKey, challenge, signatureBytes);
                }
                if (!ok)
                {
                    ok = CryptoUtils.VerifySignaturePssAuto(serverKey, challenge, signatureBytes);
                }
                if (!ok)
                {
                    Console.WriteLine($"[auth] server_auth_challenge payload={payload.GetRawText()}");
                    Console.WriteLine($"[auth] challenge='{challenge}' sig.len={signatureBytes.Length} key.len={serverPem.Length}");
                    Console.WriteLine($"[auth] challenge.len={challenge.Length} hex={Convert.ToHexString(Encoding.UTF8.GetBytes(challenge))}");
                    LoginStatus = "Falha na autenticação do servidor: assinatura inválida";
                    return;
                }

                var pinnedKey = LoadPinnedServerPublicKey(ServerAddress);
                if (!string.IsNullOrWhiteSpace(pinnedKey))
                {
                    var currentNorm = NormalizePublicKeyB64ForComparison(serverPublicKeyB64);
                    var pinnedNorm = NormalizePublicKeyB64ForComparison(pinnedKey);
                    if (!string.Equals(currentNorm, pinnedNorm, StringComparison.OrdinalIgnoreCase))
                    {
                        LoginStatus = "Falha na autenticação do servidor: chave pública mudou (pinning ativo).";
                        return;
                    }
                }
                else
                {
                    SavePinnedServerPublicKey(ServerAddress, serverPublicKeyB64);
                }

                _serverPublicKeys[ServerAddress] = serverPublicKeyB64;
                _clientAuthChallenge = GenerateToken();
                if (_privateKey is null)
                {
                    LoginStatus = "Falha ao assinar desafio do cliente";
                    return;
                }

                var clientSignature = CryptoUtils.SignPayload(_privateKey, _clientAuthChallenge);
                var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));

                await _socketClient.EmitAsync("verify_server_auth_response", new
                {
                    client_challenge = _clientAuthChallenge,
                    client_signature = Convert.ToBase64String(clientSignature),
                    client_public_key = publicKeyB64
                });

                LoginStatus = "Servidor autenticado. Preparando login...";
            }
            catch
            {
                LoginStatus = "Erro na autenticação do servidor";
            }
        });

        _socketClient.OnAsync("server_auth_result", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
                LoginStatus = $"Falha na autenticação do servidor: {error}";
                LogCli($"[cli] server_auth_result failed: {error}");
                return;
            }

            LoginStatus = "Servidor autenticado com sucesso";
            if (!string.IsNullOrWhiteSpace(Username))
            {
                LogCli("[cli] solicitando contrato de uso");
                await _socketClient.EmitAsync("request_usage_contract", new
                {
                    username = Username.Trim()
                });
            }
            else
            {
                LogCli("[cli] usuario vazio, nao solicitou contrato de uso");
            }
        });

        _socketClient.On("ban_notification", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var reason = payload.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() ?? "Banido" : "Banido";
            var duration = payload.TryGetProperty("duration", out var durProp) ? durProp.GetInt32() : 0;
            BanStatus = duration > 0 ? $"Banido por {duration}s: {reason}" : $"Banido: {reason}";
            Status = "Banido";
        });

        _socketClient.On("status", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var message = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(message))
            {
                Status = message;
            }
        });

        _socketClient.OnAsync("usage_contract_required", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            LogCli("[cli] contrato de uso requerido");
            await HandleUsageContractRequiredAsync(payload);
        });

        _socketClient.OnAsync("usage_contract_status", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
                LoginStatus = $"Falha no contrato de uso: {error}";
                return;
            }

            var required = payload.TryGetProperty("required", out var reqProp) && reqProp.GetBoolean();
            if (!required)
            {
                LogCli("[cli] contrato de uso nao requerido, solicitando PoW login");
                await RequestPowChallengeAsync("login");
            }
        });

        _socketClient.OnAsync("usage_contract_ack", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
            {
                var message = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() : "Transação em análise.";
                LoginStatus = message ?? "Transação em análise.";
                LogCli($"[cli] contrato de uso pendente: {message}");
                return;
            }

            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
                LoginStatus = $"Falha no contrato de uso: {error}";
                LogCli($"[cli] contrato de uso falhou: {error}");
                ReleasePendingHpsPayment("usage_contract");
                return;
            }

            var deferredPayment = payload.TryGetProperty("deferred_payment", out var deferredProp) && deferredProp.GetBoolean();
            ClearPendingHpsPayment("usage_contract");
            if (deferredPayment)
            {
                LoginStatus = "Contrato de uso aceito. Continue o login para prosseguir.";
                LogCli("[cli] contrato de uso aceito via minerador; nao solicitar PoW login automaticamente");
                return;
            }

            LoginStatus = "Contrato de uso aceito. Iniciando PoW...";
            LogCli("[cli] contrato de uso aceito, solicitando PoW login");
            await RequestPowChallengeAsync("login");
        });

        _socketClient.OnAsync("pow_challenge", async response =>
        {
            _powChallengeTimeoutCts?.Cancel();
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out var errProp))
            {
                LoginStatus = $"Erro PoW: {errProp.GetString()}";
                PowStatus = $"Erro PoW: {errProp.GetString()}";
                AppendImportantFlowLog($"Erro PoW: {errProp.GetString()}");
                IsPowActive = false;
                LogCli($"[cli] erro PoW: {errProp.GetString()}");
                if (string.Equals(_importantFlowKind, "pow", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
                return;
            }

            var challenge = payload.TryGetProperty("challenge", out var chalProp) ? chalProp.GetString() : null;
            var targetBits = payload.TryGetProperty("target_bits", out var bitsProp) ? bitsProp.GetInt32() : 0;
            var actionType = payload.TryGetProperty("action_type", out var actProp) ? actProp.GetString() : "login";
            var voucherId = payload.TryGetProperty("voucher_id", out var voucherProp) ? voucherProp.GetString() : null;
            var pendingDebtWarning = payload.TryGetProperty("pending_debt_warning", out var warnProp) && warnProp.GetBoolean();

            if (string.IsNullOrWhiteSpace(challenge) || targetBits <= 0)
            {
                LoginStatus = "Desafio PoW inválido";
                PowStatus = "Desafio PoW inválido";
                LogCli("[cli] desafio PoW invalido");
                return;
            }

            _lastPowActionType = actionType;
            PowActionType = actionType ?? string.Empty;
            PowTargetBits = targetBits;
            PowAttempts = "0";
            PowElapsed = "0s";
            PowHashrate = "0";
            PowStatus = $"Resolvendo PoW: {targetBits} bits";
            LoginStatus = $"Resolvendo PoW: {targetBits} bits";
            if (string.Equals(_importantFlowKind, "pow", StringComparison.OrdinalIgnoreCase))
            {
                UpdateImportantFlowStatus($"Resolvendo PoW: {targetBits} bits");
            }
            IsPowActive = true;
            AppendPowLog($"Desafio recebido: {targetBits} bits ({actionType}).");
            LogCli($"[cli] desafio PoW recebido: {targetBits} bits ({actionType})");
            if (pendingDebtWarning)
            {
                AppendPowLog("Aviso: pendências do minerador próximas do limite.");
                HpsMintStatus = "Aviso: pendências do minerador próximas do limite.";
            }
            CancelPowMonitorClose();
            ShowPowMonitor();
            if (!string.IsNullOrWhiteSpace(voucherId) && string.Equals(actionType, "hps_mint", StringComparison.OrdinalIgnoreCase))
            {
                _pendingHpsMintVoucherId = voucherId;
            }
            if (string.Equals(actionType, "hps_mint", StringComparison.OrdinalIgnoreCase))
            {
                HpsMiningStatus = "Iniciando...";
                HpsMiningBits = targetBits.ToString();
                HpsMiningElapsed = "0.0s";
                HpsMiningHashrate = "0 H/s";
                HpsMiningAttempts = "0";
                AppendPowLog($"Mineração: alvo {targetBits} bits.");
            }

            var solver = new PowSolver();
            var challengeBytes = Convert.FromBase64String(challenge);
            _powCts?.Cancel();
            _powCts = new CancellationTokenSource();
            var result = await solver.SolveAsync(challengeBytes, targetBits, PowThreads, _powCts.Token, progress =>
            {
                RunOnUi(() =>
                {
                    PowAttempts = progress.Attempts.ToString();
                    PowElapsed = $"{progress.Elapsed.TotalSeconds:0.0}s";
                    PowHashrate = $"{progress.Hashrate:0.##}/s";
                    if (string.Equals(actionType, "hps_mint", StringComparison.OrdinalIgnoreCase))
                    {
                        HpsMiningStatus = "Minerando";
                        HpsMiningElapsed = $"{progress.Elapsed.TotalSeconds:0.0}s";
                        HpsMiningHashrate = $"{progress.Hashrate:0} H/s";
                        HpsMiningAttempts = progress.Attempts.ToString();
                    }
                });
            });
            if (result is null)
            {
                if (_powCts.IsCancellationRequested)
                {
                    PowStatus = "PoW cancelado";
                    AppendPowLog("PoW cancelado.");
                }
                else
                {
                    LoginStatus = "PoW não resolvido";
                    PowStatus = "PoW não resolvido";
                    AppendPowLog("PoW não resolvido.");
                }
                IsPowActive = false;
                _ = Task.Run(TryRunDeferredAutoSignAsync);
                if (string.Equals(_importantFlowKind, "pow", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
                return;
            }

            var hashrate = result.Attempts / Math.Max(1, result.Elapsed.TotalSeconds);
            PowAttempts = result.Attempts.ToString();
            PowElapsed = $"{result.Elapsed.TotalSeconds:0.0}s";
            PowHashrate = $"{hashrate:0.##}/s";
            PowStatus = "PoW resolvido";
            AppendPowLog($"PoW resolvido em {result.Elapsed.TotalSeconds:0.00}s ({hashrate:0} H/s).");
            UpdatePowTotals(result.Elapsed.TotalSeconds);
            SchedulePowMonitorClose();
            IsPowActive = false;
            _ = Task.Run(TryRunDeferredAutoSignAsync);
            if (string.Equals(_importantFlowKind, "pow", StringComparison.OrdinalIgnoreCase))
            {
                MarkImportantFlowDone();
            }
            if (string.Equals(actionType, "hps_mint", StringComparison.OrdinalIgnoreCase))
            {
                HpsMiningStatus = "Solução encontrada";
                HpsMiningElapsed = $"{result.Elapsed.TotalSeconds:0.0}s";
                HpsMiningHashrate = $"{hashrate:0} H/s";
                HpsMiningAttempts = result.Attempts.ToString();
                var count = int.TryParse(HpsMiningCount, out var current) ? current : 0;
                count++;
                HpsMiningCount = count.ToString();
                var totalSeconds = double.TryParse(HpsMiningTotalTime.TrimEnd('s'), out var total) ? total : 0.0;
                totalSeconds += result.Elapsed.TotalSeconds;
                HpsMiningTotalTime = $"{(int)totalSeconds}s";
            }
            if (string.Equals(actionType, "login", StringComparison.OrdinalIgnoreCase))
            {
                await SendAuthenticationAsync(result.Nonce, hashrate);
            }
            else if (string.Equals(actionType, "dns", StringComparison.OrdinalIgnoreCase))
            {
                await SubmitPendingDnsAsync(result.Nonce, hashrate);
            }
            else if (string.Equals(actionType, "upload", StringComparison.OrdinalIgnoreCase))
            {
                await SubmitPendingUploadAsync(result.Nonce, hashrate);
            }
            else if (string.Equals(actionType, "usage_contract", StringComparison.OrdinalIgnoreCase))
            {
                await SubmitPendingUsageContractAsync(result.Nonce, hashrate);
            }
            else if (string.Equals(actionType, "hps_transfer", StringComparison.OrdinalIgnoreCase))
            {
                await SubmitPendingHpsTransferAsync(result.Nonce, hashrate);
            }
            else if (string.Equals(actionType, "hps_mint", StringComparison.OrdinalIgnoreCase))
            {
                await SubmitHpsMintAsync(result.Nonce, hashrate);
            }
            else if (string.Equals(actionType, "inventory_transfer", StringComparison.OrdinalIgnoreCase))
            {
                if (_pendingInventoryTransfer is not null)
                {
                    await SendInventoryTransferRequestAsync(
                        _pendingInventoryTransfer.Item,
                        _pendingInventoryTransfer.Owner,
                        result.Nonce,
                        hashrate,
                        null
                    );
                    _pendingInventoryTransfer = null;
                }
            }
            else if (string.Equals(actionType, "contract_transfer", StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(_pendingTransferType, "hps_transfer", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(_pendingTransferAction, "accept", StringComparison.OrdinalIgnoreCase))
                {
                    await _socketClient.EmitAsync("accept_hps_transfer", new
                    {
                        transfer_id = _pendingTransferId,
                        pow_nonce = result.Nonce.ToString(),
                        hashrate_observed = hashrate
                    });
                }
                else
                {
                    var eventName = string.Equals(_pendingTransferAction, "renounce", StringComparison.OrdinalIgnoreCase)
                        ? "renounce_transfer"
                        : "reject_transfer";
                    await _socketClient.EmitAsync(eventName, new
                    {
                        transfer_id = _pendingTransferId,
                        pow_nonce = result.Nonce.ToString(),
                        hashrate_observed = hashrate
                    });
                }
            }
            else if (string.Equals(actionType, "contract_certify", StringComparison.OrdinalIgnoreCase))
            {
                await SubmitPendingCriticalContractCertificationAsync(result.Nonce, hashrate);
            }
        });

        _socketClient.OnAsync("authentication_result", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
                LoginStatus = $"Falha no login: {error}";
                IsLoggedIn = false;
                UpdateImportantFlowStatus($"Falha no login: {error}");
                MarkImportantFlowDone();
                LogCli($"[cli] login falhou: {error}");
                _authenticationResultTcs?.TrySetResult(false);
                return;
            }

            var username = payload.TryGetProperty("username", out var userProp) ? userProp.GetString() : Username;
            var reputation = payload.TryGetProperty("reputation", out var repProp) ? repProp.GetInt32() : 100;
            User = username ?? "Conectado";
            Reputation = reputation.ToString();
            Status = "Conectado";
            LoginStatus = "Login bem-sucedido!";
            IsLoggedIn = true;
            UpdateImportantFlowStatus("Login concluído. Sessão protegida aberta com sucesso.");
            MarkImportantFlowDone();
            LogCli("[cli] login bem-sucedido");
            _authenticationResultTcs?.TrySetResult(true);
            HpsMiningStatus = _socketClient.IsConnected ? "Pronto" : "Aguardando conexão";
            ResetSessionStats();
            _ = BootstrapAfterLoginAsync();
        });

        _socketClient.On("dns_result", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
            {
                var message = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() : "Transação em análise.";
                DnsStatus = message ?? "Transação em análise.";
                MovePendingHpsPaymentToWalletSync("dns");
                return;
            }

            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (success)
            {
                var domain = payload.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() : string.Empty;
                DnsStatus = $"DNS registrado: {domain}";
                if (!string.IsNullOrWhiteSpace(domain))
                {
                    IncrementDnsRegistered(domain);
                }
                ClearPendingHpsPayment("dns");
                LoadDnsRecords();
                if (string.Equals(_importantFlowKind, "dns", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
            }
            else
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
                DnsStatus = $"Falha no registro DNS: {error}";
                ReleasePendingHpsPayment("dns");
                if (string.Equals(_importantFlowKind, "dns", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
            }
        });

        _socketClient.OnAsync("dns_resolution", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
                if (string.Equals(error, "contract_violation", StringComparison.OrdinalIgnoreCase))
                {
                    var reason = payload.TryGetProperty("contract_violation_reason", out var reasonProp)
                        ? reasonProp.GetString() ?? "contract_violation"
                        : "contract_violation";
                    var blockedDomain = payload.TryGetProperty("domain", out var blockedDomainProp) ? blockedDomainProp.GetString() ?? string.Empty : string.Empty;
                    RegisterContractViolation("domain", blockedDomain, reason);
                    DnsStatus = "DNS bloqueado por violação contratual.";
                    ShowCriticalBrowserError(
                        BuildCriticalErrorCode(reason),
                        "DNS bloqueado",
                        $"O domínio {blockedDomain} não foi aberto porque falhou em uma validação crítica: {DescribeCriticalReason(reason)}",
                        "domain",
                        blockedDomain,
                        reason);
                    StartContractAlert(IsCertifiableContractReason(reason)
                        ? "Este conteúdo tem uma pendência contratual certificável."
                        : "Este conteúdo tem uma violação contratual crítica.");
                }
                else if (string.Equals(error, "issuer_verification_pending", StringComparison.OrdinalIgnoreCase))
                {
                    var jobId = payload.TryGetProperty("job_id", out var jobProp) ? jobProp.GetString() ?? string.Empty : string.Empty;
                    var miner = payload.TryGetProperty("assigned_miner", out var minerProp) ? minerProp.GetString() ?? string.Empty : string.Empty;
                    DnsStatus = string.IsNullOrWhiteSpace(miner)
                        ? $"Checagem de emissão pendente ({jobId})."
                        : $"Checagem de emissão pendente ({jobId}) com minerador {miner}.";
                }
                else
                {
                    DnsStatus = $"Falha ao resolver DNS: {error}";
                }
                if (string.Equals(_importantFlowKind, "dns", StringComparison.OrdinalIgnoreCase))
                {
                    UpdateImportantFlowStatus(DnsStatus);
                    MarkImportantFlowDone();
                }
                return;
            }

            var domain = payload.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() : string.Empty;
            var contentHash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() : string.Empty;
            var username = payload.TryGetProperty("username", out var userProp) ? userProp.GetString() : string.Empty;
            var verified = payload.TryGetProperty("verified", out var verProp) && verProp.GetBoolean();

            var contracts = payload.TryGetProperty("contracts", out var contractsProp) && contractsProp.ValueKind == JsonValueKind.Array
                ? ParseContractsList(contractsProp)
                : new List<string>();
            var signature = payload.TryGetProperty("signature", out var sigProp) ? sigProp.GetString() ?? string.Empty : string.Empty;
            var publicKey = payload.TryGetProperty("public_key", out var keyProp) ? keyProp.GetString() ?? string.Empty : string.Empty;
            var originalOwner = payload.TryGetProperty("original_owner", out var ownerProp) ? ownerProp.GetString() ?? string.Empty : string.Empty;
            var certifier = payload.TryGetProperty("certifier", out var certProp) ? certProp.GetString() ?? string.Empty : string.Empty;
            if (payload.TryGetProperty("contracts", out var dnsContractsProp) && dnsContractsProp.ValueKind == JsonValueKind.Array)
            {
                SaveContractsFromPayload(dnsContractsProp);
                await RequestContractsFromPayloadAsync(dnsContractsProp);
            }
            _lastDomainInfo = new DomainSecurityInfo(
                domain ?? string.Empty,
                contentHash ?? string.Empty,
                username ?? string.Empty,
                originalOwner,
                verified,
                signature,
                contracts,
                certifier
            );

            DnsStatus = $"DNS Resolvido: {domain}";
            if (string.Equals(_importantFlowKind, "dns", StringComparison.OrdinalIgnoreCase))
            {
                UpdateImportantFlowStatus($"DNS Resolvido: {domain}");
                MarkImportantFlowDone();
            }
            if (!string.IsNullOrWhiteSpace(domain) && !string.IsNullOrWhiteSpace(contentHash))
            {
                if (payload.TryGetProperty("ddns_content", out var ddnsProp) &&
                    ddnsProp.ValueKind == JsonValueKind.String &&
                    !string.IsNullOrWhiteSpace(ddnsProp.GetString()))
                {
                    try
                    {
                        var ddnsBytes = Convert.FromBase64String(ddnsProp.GetString() ?? string.Empty);
                        var ddnsHash = payload.TryGetProperty("ddns_hash", out var ddnsHashProp)
                            ? ddnsHashProp.GetString() ?? string.Empty
                            : string.Empty;
                        if (string.IsNullOrWhiteSpace(ddnsHash))
                        {
                            ddnsHash = _contentService.ComputeSha256HexBytes(ddnsBytes);
                        }
                        _contentService.SaveDdnsToStorage(domain, ddnsBytes, ddnsHash, contentHash, username ?? string.Empty, signature, publicKey);
                    }
                    catch
                    {
                        _database.SaveDnsRecord(domain, contentHash, username ?? string.Empty, verified);
                    }
                }
                else
                {
                    _database.SaveDnsRecord(domain, contentHash, username ?? string.Empty, verified);
                }
                LoadDnsRecords();
                ScheduleClientPropagationSync();
                BrowserUrl = $"hps://{contentHash}";
                _ = RequestContentByHashAsync(contentHash);
            }
        });

        _socketClient.OnAsync("content_response", async response =>
        {
            var payload = response.GetValue<JsonElement>();
                if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
                {
                var message = payload.TryGetProperty("message", out var msgProp)
                    ? msgProp.GetString() ?? "Buscando conteúdo na rede..."
                    : "Buscando conteúdo na rede...";
                BrowserContent = message;
                if (string.Equals(_importantFlowKind, "content", StringComparison.OrdinalIgnoreCase))
                {
                    UpdateImportantFlowStatus(message);
                }
                IsBrowserImageVisible = false;
                IsBrowserTextVisible = true;
                return;
            }
            if (payload.TryGetProperty("error", out var errProp))
            {
                var errorText = errProp.GetString() ?? "Erro desconhecido";
                if (string.Equals(errorText, "contract_violation", StringComparison.OrdinalIgnoreCase))
                {
                    var reason = payload.TryGetProperty("contract_violation_reason", out var reasonProp)
                        ? reasonProp.GetString() ?? "contract_violation"
                        : "contract_violation";
                    var blockedContentHash = payload.TryGetProperty("content_hash", out var blockedHashProp)
                        ? blockedHashProp.GetString() ?? string.Empty
                        : string.Empty;
                    RegisterContractViolation("content", blockedContentHash, reason);
                    BrowserContent = "Conteúdo bloqueado por violação contratual.";
                    ShowCriticalBrowserError(
                        BuildCriticalErrorCode(reason),
                        "Conteúdo bloqueado",
                        $"O arquivo {blockedContentHash} não foi aberto porque falhou em uma validação crítica: {DescribeCriticalReason(reason)}",
                        "content",
                        blockedContentHash,
                        reason);
                    StartContractAlert("Você está com pendências contratuais.");
                }
                else if (string.Equals(errorText, "issuer_verification_pending", StringComparison.OrdinalIgnoreCase))
                {
                    var jobId = payload.TryGetProperty("job_id", out var jobProp) ? jobProp.GetString() ?? string.Empty : string.Empty;
                    var miner = payload.TryGetProperty("assigned_miner", out var minerProp) ? minerProp.GetString() ?? string.Empty : string.Empty;
                    var issuerContentHash = payload.TryGetProperty("content_hash", out var issuerHashProp)
                        ? issuerHashProp.GetString() ?? string.Empty
                        : string.Empty;
                    BrowserContent = string.IsNullOrWhiteSpace(miner)
                        ? $"Aguardando checagem de emissão ({jobId})."
                        : $"Aguardando checagem de emissão ({jobId}) pelo minerador {miner}.";
                    if (string.Equals(_importantFlowKind, "content", StringComparison.OrdinalIgnoreCase))
                    {
                        UpdateImportantFlowStatus(BrowserContent);
                        ImportantFlowDetails = string.IsNullOrWhiteSpace(miner)
                            ? $"Hash: {issuerContentHash}\nJob: {jobId}\nNenhum minerador atribuído ainda."
                            : $"Hash: {issuerContentHash}\nJob: {jobId}\nMinerador: {miner}";
                        SyncImportantFlowDetailPopup();
                    }
                }
                else
                {
                    BrowserContent = $"Erro no conteúdo: {errorText}";
                    ShowCriticalBrowserError("HPS-CONTENT-ERROR", "Erro crítico ao abrir conteúdo", errorText);
                }
                IsBrowserImageVisible = false;
                IsBrowserTextVisible = true;
                if (string.Equals(_importantFlowKind, "content", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(errorText, "issuer_verification_pending", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
                return;
            }

            var contentB64 = payload.TryGetProperty("content", out var contentProp) ? contentProp.GetString() : null;
            var title = payload.TryGetProperty("title", out var titleProp) ? titleProp.GetString() : "Sem título";
            var description = payload.TryGetProperty("description", out var descProp) ? descProp.GetString() : string.Empty;
            var mimeType = payload.TryGetProperty("mime_type", out var mimeProp) ? mimeProp.GetString() : "text/plain";
            var username = payload.TryGetProperty("username", out var userProp) ? userProp.GetString() ?? string.Empty : string.Empty;
            var contentHash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() : string.Empty;
            var signatureB64 = payload.TryGetProperty("signature", out var sigProp) ? sigProp.GetString() ?? string.Empty : string.Empty;
            var publicKey = payload.TryGetProperty("public_key", out var keyProp) ? keyProp.GetString() ?? string.Empty : string.Empty;

            if (string.IsNullOrWhiteSpace(contentB64))
            {
                BrowserContent = "Conteúdo vazio.";
                IsBrowserImageVisible = false;
                IsBrowserTextVisible = true;
                return;
            }

            try
            {
                var validation = await Task.Run(() => ValidateContentResponseData(
                    contentB64,
                    contentHash ?? string.Empty,
                    username,
                    signatureB64,
                    publicKey)).ConfigureAwait(true);

                _lastContentHash = contentHash ?? string.Empty;
                _lastContentPublicKey = publicKey ?? string.Empty;
                _lastContentSignatureValid = validation.SignatureValid;
                if (!validation.Success)
                {
                    BrowserContent = validation.BrowserMessage;
                    if (!string.IsNullOrWhiteSpace(validation.CriticalCode))
                    {
                        ShowCriticalBrowserError(
                            validation.CriticalCode,
                            validation.CriticalTitle,
                            validation.CriticalDetail,
                            "content",
                            contentHash ?? string.Empty,
                            validation.Reason);
                    }
                    _lastContentBytes = null;
                    RaiseCommandCanExecuteChanged();
                    IsBrowserImageVisible = false;
                    IsBrowserTextVisible = true;
                    if (!string.IsNullOrWhiteSpace(contentHash) && !string.IsNullOrWhiteSpace(validation.Reason))
                    {
                        await ReportContentTamperAsync(contentHash, validation.Reason);
                    }
                    return;
                }
                if (!string.IsNullOrWhiteSpace(contentHash))
                {
                    ClearContractViolation("content", contentHash);
                    DismissCriticalBrowserErrorForTarget("content", contentHash);
                    if (string.Equals(_importantFlowKind, "content", StringComparison.OrdinalIgnoreCase))
                    {
                        UpdateImportantFlowStatus($"Conteúdo validado: {contentHash}");
                    }
                }
                var data = validation.Data;
                var hasContracts = payload.TryGetProperty("contracts", out var contractsProp) && contractsProp.ValueKind == JsonValueKind.Array;
                var contracts = hasContracts ? ParseContractsList(contractsProp) : new List<string>();
                if (hasContracts)
                {
                    SaveContractsFromPayload(contractsProp);
                    await RequestContractsFromPayloadAsync(contractsProp);
                }
                var originalOwner = payload.TryGetProperty("original_owner", out var ownerProp) ? ownerProp.GetString() ?? string.Empty : string.Empty;
                var certifier = payload.TryGetProperty("certifier", out var certProp) ? certProp.GetString() ?? string.Empty : string.Empty;
                var reputation = payload.TryGetProperty("reputation", out var repProp) ? repProp.GetInt32() : 0;
                _lastContentInfo = new ContentSecurityInfo(
                    title ?? string.Empty,
                    description ?? string.Empty,
                    username ?? string.Empty,
                    originalOwner,
                    contentHash ?? string.Empty,
                    mimeType ?? "application/octet-stream",
                    signatureB64,
                    publicKey ?? string.Empty,
                    _lastContentSignatureValid,
                    reputation,
                    contracts,
                    certifier
                );

                var contentHashValue = contentHash ?? string.Empty;
                if (string.Equals(title, DnsChangeTitle, StringComparison.Ordinal))
                {
                    var hasTransferContract = hasContracts && HasContractAction(contractsProp, "transfer_domain");
                    if (!hasTransferContract && !string.IsNullOrWhiteSpace(contentHashValue))
                    {
                        await EmitContractViolationAsync("content", contentHashValue, string.Empty, "missing_transfer_contract");
                        RegisterContractViolation("content", contentHashValue, "missing_transfer_contract");
                    }
                }

                var appName = ExtractApiAppName(title ?? string.Empty);
                var isApiApp = !string.IsNullOrWhiteSpace(appName) ||
                               (!string.IsNullOrWhiteSpace(title) && title.StartsWith("(HPS!api)", StringComparison.OrdinalIgnoreCase));
                if (isApiApp && !string.IsNullOrWhiteSpace(contentHashValue))
                {
                    if (_apiAppBypassHashes.Remove(contentHashValue))
                    {
                        RenderContent(data, title ?? string.Empty, description ?? string.Empty, mimeType ?? "application/octet-stream");
                    }
                    else
                    {
                        BrowserContent = "Buscando versões do API app...";
                        IsBrowserImageVisible = false;
                        IsBrowserTextVisible = true;
                        await RequestApiAppVersionsAsync(appName, title ?? string.Empty, contentHashValue, _lastContentInfo, data, mimeType ?? "application/octet-stream", null);
                        return;
                    }
                }
                else
                {
                    RenderContent(data, title ?? string.Empty, description ?? string.Empty, mimeType ?? "application/octet-stream");
                }

                if (!string.IsNullOrWhiteSpace(contentHash))
                {
                    _contentService.SaveContentToStorage(contentHash, data, title ?? string.Empty, description ?? string.Empty, mimeType ?? "application/octet-stream", signatureB64, publicKey ?? string.Empty, username ?? string.Empty);
                    IncrementContentDownloaded(contentHash);
                    LoadLocalInventory();
                    ScheduleClientPropagationSync();
                }
                if (string.Equals(_importantFlowKind, "content", StringComparison.OrdinalIgnoreCase))
                {
                    UpdateImportantFlowStatus("Conteúdo carregado no browser.");
                    MarkImportantFlowDone();
                }
            }
            catch
            {
                BrowserContent = "Falha ao decodificar conteúdo.";
                IsBrowserImageVisible = false;
                IsBrowserTextVisible = true;
                if (string.Equals(_importantFlowKind, "content", StringComparison.OrdinalIgnoreCase))
                {
                    UpdateImportantFlowStatus("Falha ao decodificar conteúdo.");
                    MarkImportantFlowDone();
                }
            }
        });

        _socketClient.On("search_results", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out var errProp))
            {
                SearchStatus = $"Falha na busca: {errProp.GetString()}";
                return;
            }
            if (!payload.TryGetProperty("results", out var resultsProp) || resultsProp.ValueKind != JsonValueKind.Array)
            {
                SearchStatus = "Nenhum resultado encontrado.";
                SearchResults.Clear();
                return;
            }

            SearchResults.Clear();
            foreach (var resultElem in resultsProp.EnumerateArray())
            {
                var result = ParseSearchResult(resultElem);
                if (result is not null)
                {
                    SearchResults.Add(result);
                }
            }
            SearchStatus = $"Resultados: {SearchResults.Count}";
        });

        _socketClient.On("content_search_status", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var status = payload.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? string.Empty : string.Empty;
            if (string.Equals(status, "running", StringComparison.OrdinalIgnoreCase))
            {
                SearchStatus = "Buscando...";
            }
            else if (string.Equals(status, "done", StringComparison.OrdinalIgnoreCase))
            {
                var count = payload.TryGetProperty("count", out var countProp) ? countProp.GetInt32() : SearchResults.Count;
                SearchStatus = $"Resultados: {count}";
            }
            else if (string.Equals(status, "error", StringComparison.OrdinalIgnoreCase))
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
                SearchStatus = $"Falha na busca: {error}";
            }
        });

        _socketClient.On("upload_result", response =>
        {
            var payload = response.GetValue<JsonElement>();
            RunOnUi(() => HandleUploadResult(payload, true));
        });

        _socketClient.On("publish_result", response =>
        {
            var payload = response.GetValue<JsonElement>();
            RunOnUi(() => HandleUploadResult(payload, true));
        });

        _socketClient.On("action_queue_update", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var action = payload.TryGetProperty("action", out var actionProp) ? actionProp.GetString() ?? string.Empty : string.Empty;
            var status = payload.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? string.Empty : string.Empty;
            var position = payload.TryGetProperty("position", out var positionProp) && positionProp.ValueKind == JsonValueKind.Number
                ? positionProp.GetInt32()
                : 0;
            UpdateActionQueueStatus(action, status, position);
        });

        _socketClient.On("hps_wallet_sync", response =>
        {
            var payload = response.GetValue<JsonElement>();
            _ = HandleWalletSyncAsync(payload);
        });

        _socketClient.On("hps_vouchers_ghosted", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (!payload.TryGetProperty("voucher_ids", out var voucherIdsProp) || voucherIdsProp.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            var voucherIds = voucherIdsProp
                .EnumerateArray()
                .Select(item => item.GetString() ?? string.Empty)
                .Where(id => !string.IsNullOrWhiteSpace(id))
                .ToList();
            if (voucherIds.Count == 0)
            {
                return;
            }

            MarkVouchersGhosted(voucherIds);
            var issuer = payload.TryGetProperty("issuer", out var issuerProp) ? issuerProp.GetString() ?? string.Empty : string.Empty;
            var reason = payload.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() ?? "exchange_out" : "exchange_out";
            ExchangeStatus = string.IsNullOrWhiteSpace(issuer)
                ? $"Vouchers marcados como ghosted ({reason})."
                : $"Vouchers de {issuer} marcados como ghosted ({reason}).";
        });

        _socketClient.On("hps_transfer_ack", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
            {
                var message = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() : "Transação em análise.";
                HpsActionStatus = message ?? "Transação em análise.";
                return;
            }

            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp2) ? errProp2.GetString() : "Erro desconhecido";
                if (_pendingHpsTransfer is not null)
                {
                    ReleaseLocalVouchers(_pendingHpsTransfer.VoucherIds);
                }
                HpsActionStatus = $"Falha na transferência HPS: {error}";
                ReleasePendingHpsPayment("hps_transfer");
                return;
            }

            HpsActionStatus = "Transferência HPS enviada.";
            _pendingHpsTransfer = null;
            ClearPendingHpsPayment("hps_transfer");
        });

        _socketClient.On("network_state", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out _))
            {
                return;
            }

            var online = payload.TryGetProperty("online_nodes", out var onlineProp) ? onlineProp.GetInt32() : 0;
            var totalContent = payload.TryGetProperty("total_content", out var contentProp) ? contentProp.GetInt32() : 0;
            var totalDns = payload.TryGetProperty("total_dns", out var dnsProp) ? dnsProp.GetInt32() : 0;
            NetworkStats = $"Nós: {online} | Conteúdo: {totalContent} | DNS: {totalDns}";
            NetworkStatus = string.Empty;
        });

        _socketClient.On("network_joined", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Falha ao entrar na rede";
                NetworkStatus = error ?? "Falha ao entrar na rede";
                return;
            }
            NetworkStatus = "Entrada na rede confirmada.";
        });

        _socketClient.On("backup_server", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var server = payload.TryGetProperty("server", out var serverProp) ? serverProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(server))
            {
                NetworkStatus = $"Servidor de backup: {server}";
            }
        });

        _socketClient.On("server_list", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out _))
            {
                return;
            }

            if (!_hasNetworkNodesSnapshot)
            {
                NetworkNodes.Clear();
            }
            if (!payload.TryGetProperty("servers", out var serversProp) || serversProp.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            foreach (var server in serversProp.EnumerateArray())
            {
                var address = server.TryGetProperty("address", out var addrProp) ? addrProp.GetString() ?? string.Empty : string.Empty;
                var reputation = server.TryGetProperty("reputation", out var repProp2) ? repProp2.GetInt32() : 100;
                var normalizedAddress = NormalizeServerAddressInput(address);
                if (string.IsNullOrWhiteSpace(normalizedAddress))
                {
                    continue;
                }
                if (!string.IsNullOrWhiteSpace(normalizedAddress) &&
                    !KnownServers.Any(s => string.Equals(s.Address, normalizedAddress, StringComparison.OrdinalIgnoreCase)))
                {
                    KnownServers.Add(new ServerInfo
                    {
                        Address = normalizedAddress,
                        UseSsl = normalizedAddress.StartsWith("https://", StringComparison.OrdinalIgnoreCase),
                        Status = "Descoberto",
                        Reputation = reputation
                    });
                }
                var existingServerNode = NetworkNodes.FirstOrDefault(n =>
                    string.Equals(n.NodeType, "server", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(n.Address, normalizedAddress, StringComparison.OrdinalIgnoreCase));
                if (existingServerNode is not null)
                {
                    existingServerNode.Reputation = reputation;
                    existingServerNode.Status = "Ativo";
                    continue;
                }
                NetworkNodes.Add(new NetworkNodeInfo
                {
                    NodeId = $"server:{normalizedAddress}",
                    Username = normalizedAddress,
                    Address = normalizedAddress,
                    NodeType = "server",
                    Reputation = reputation,
                    Status = "Ativo"
                });
            }
            SaveKnownServers();
            _networkNodesView?.Refresh();
            RefreshMessageTargetOptions();
            NetworkStatus = string.Empty;
        });

        _socketClient.On("network_nodes", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out _))
            {
                return;
            }

            _hasNetworkNodesSnapshot = true;
            NetworkNodes.Clear();
            if (!payload.TryGetProperty("nodes", out var nodesProp) || nodesProp.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            foreach (var node in nodesProp.EnumerateArray())
            {
                var nodeId = node.TryGetProperty("node_id", out var nodeIdProp) ? nodeIdProp.GetString() ?? string.Empty : string.Empty;
                var username = node.TryGetProperty("username", out var userProp) ? userProp.GetString() ?? string.Empty : string.Empty;
                var address = node.TryGetProperty("address", out var addrProp) ? addrProp.GetString() ?? string.Empty : string.Empty;
                var nodeType = node.TryGetProperty("node_type", out var typeProp) ? typeProp.GetString() ?? string.Empty : string.Empty;
                var reputation = node.TryGetProperty("reputation", out var repProp2) ? repProp2.GetInt32() : 100;
                var status = node.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? string.Empty : string.Empty;
                var isOnline = node.TryGetProperty("is_online", out var onlineProp) && onlineProp.GetBoolean();
                NetworkNodes.Add(new NetworkNodeInfo
                {
                    NodeId = nodeId,
                    Username = username,
                    Address = address,
                    NodeType = string.IsNullOrWhiteSpace(nodeType) ? "client" : nodeType,
                    Reputation = reputation,
                    Status = string.IsNullOrWhiteSpace(status) ? (isOnline ? "Ativo" : "Offline") : status
                });
            }

            _networkNodesView?.Refresh();
            RefreshMessageTargetOptions();
            NetworkStatus = string.Empty;
        });

        _socketClient.On("inventory_response", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out var errProp))
            {
                InventoryStatus = $"Falha ao obter inventório: {errProp.GetString()}";
                return;
            }

            var requestId = payload.TryGetProperty("request_id", out var reqProp) ? reqProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(_pendingInventoryRequestId) && !string.Equals(_pendingInventoryRequestId, requestId, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var inventoryPublic = payload.TryGetProperty("inventory_public", out var pubProp) && pubProp.GetBoolean();
            var targetUser = payload.TryGetProperty("target_user", out var userProp) ? userProp.GetString() ?? string.Empty : string.Empty;
            _remotePublishedInventory.Clear();
            _remoteLocalInventory.Clear();

            if (!inventoryPublic)
            {
                InventoryStatus = $"Inventório de {targetUser} está privado.";
                return;
            }

            if (payload.TryGetProperty("published", out var publishedProp) && publishedProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var itemElem in publishedProp.EnumerateArray())
                {
                    var item = BuildInventoryItemFromPayload(itemElem, targetUser, "publicado");
                    if (item is not null)
                    {
                        _remotePublishedInventory.Add(item);
                    }
                }
            }

            if (payload.TryGetProperty("local", out var localProp) && localProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var itemElem in localProp.EnumerateArray())
                {
                    var item = BuildInventoryItemFromPayload(itemElem, targetUser, "local");
                    if (item is not null)
                    {
                        _remoteLocalInventory.Add(item);
                    }
                }
            }

            InventoryStatus = $"Inventório de {targetUser} carregado.";
        });

        _socketClient.OnAsync("inventory_request", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var requestId = payload.TryGetProperty("request_id", out var reqProp) ? reqProp.GetString() ?? string.Empty : string.Empty;
            var requester = payload.TryGetProperty("requester", out var reqUserProp) ? reqUserProp.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(requestId))
            {
                return;
            }

            await _socketClient.EmitAsync("inventory_response", new
            {
                request_id = requestId,
                target_user = User,
                requester,
                inventory_public = false,
                published = Array.Empty<object>(),
                local = Array.Empty<object>()
            });
        });

        _socketClient.On("inventory_transfer_request", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var transferId = payload.TryGetProperty("transfer_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(transferId))
            {
                return;
            }
            _ = _socketClient.EmitAsync("reject_inventory_transfer", new
            {
                transfer_id = transferId,
                reason = "Unavailable"
            });
        });

        _socketClient.On("inventory_transfer_ack", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
            {
                var pendingMessage = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() ?? string.Empty : "Transação em análise.";
                InventoryStatus = pendingMessage;
                return;
            }
            if (payload.TryGetProperty("error", out var errProp))
            {
                InventoryStatus = $"Falha na solicitação de inventório: {errProp.GetString()}";
                return;
            }

            var message = payload.TryGetProperty("message", out var msgProp2) ? msgProp2.GetString() ?? string.Empty : string.Empty;
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (string.IsNullOrWhiteSpace(message))
            {
                InventoryStatus = success ? "Solicitação de inventório processada." : "Solicitação de inventório enviada.";
            }
            else
            {
                InventoryStatus = message;
            }
        });

        _socketClient.On("inventory_transfer_payload", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out var errProp))
            {
                InventoryStatus = $"Falha ao receber inventório: {errProp.GetString()}";
                return;
            }

            var contentB64 = payload.TryGetProperty("content_b64", out var contentProp) ? contentProp.GetString() : null;
            var contentHash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(contentB64) || string.IsNullOrWhiteSpace(contentHash))
            {
                InventoryStatus = "Inventório: payload inválido.";
                return;
            }

            try
            {
                var content = Convert.FromBase64String(contentB64);
                var computed = _contentService.ComputeSha256HexBytes(content);
                if (!string.Equals(computed, contentHash, StringComparison.OrdinalIgnoreCase))
                {
                    InventoryStatus = "Inventório: hash inválido.";
                    return;
                }
                var title = payload.TryGetProperty("title", out var titleProp) ? titleProp.GetString() ?? string.Empty : string.Empty;
                var description = payload.TryGetProperty("description", out var descProp) ? descProp.GetString() ?? string.Empty : string.Empty;
                var mime = payload.TryGetProperty("mime_type", out var mimeProp) ? mimeProp.GetString() ?? "application/octet-stream" : "application/octet-stream";
                var signature = payload.TryGetProperty("signature", out var sigProp) ? sigProp.GetString() ?? string.Empty : string.Empty;
                var publicKey = payload.TryGetProperty("public_key", out var keyProp) ? keyProp.GetString() ?? string.Empty : string.Empty;
                var owner = payload.TryGetProperty("owner", out var ownerProp) ? ownerProp.GetString() ?? string.Empty : string.Empty;
                _contentService.SaveContentToStorage(contentHash, content, title, description, mime, signature, publicKey, owner);
                IncrementContentDownloaded(contentHash);
                LoadLocalInventory();
                InventoryStatus = "Inventório recebido e salvo.";
            }
            catch
            {
                InventoryStatus = "Inventório: falha ao decodificar conteúdo.";
            }
        });

        _socketClient.On("inventory_transfer_rejected", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var reason = payload.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() ?? string.Empty : string.Empty;
            InventoryStatus = string.IsNullOrWhiteSpace(reason) ? "Solicitação de inventório rejeitada." : $"Solicitação rejeitada: {reason}";
        });

        _socketClient.OnAsync("hps_voucher_offer", async response =>
        {
            await HandleVoucherOfferAsync(response.GetValue<JsonElement>().Clone());
        });

        _socketClient.On("hps_voucher_withheld", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var value = payload.TryGetProperty("value", out var valueProp) ? valueProp.GetInt32() : 0;
            HpsMintStatus = value > 0 ? $"Mineração retida. Valor: {value} HPS." : "Mineração retida pelo servidor.";
            HpsMiningStatus = "Voucher pendente";
            if (value > 0)
            {
                _minerWithheldCountValue++;
                _minerWithheldValueTotal += value;
                MinerWithheldCount = _minerWithheldCountValue.ToString();
                MinerWithheldValue = $"{_minerWithheldValueTotal:0.##}";
            }
            AppendPowLog($"Voucher pendente ({value} HPS).");
            if (payload.TryGetProperty("debt_status", out var debtProp))
            {
                UpdateMinerDebtStatus(debtProp);
            }
            ScheduleNextContinuousMining();
        });

        _socketClient.On("hps_voucher_error", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
            HpsMintStatus = $"Erro na mineração: {error}";
            HpsMiningStatus = "Erro no voucher";
            AppendPowLog($"Erro no voucher: {error}");
            ScheduleNextContinuousMining();
        });

        _socketClient.On("miner_signature_update", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var pending = payload.TryGetProperty("pending_signatures", out var pendingProp) ? pendingProp.GetInt32() : 0;
            MinerPendingSignatures = pending.ToString();
            AppendPowLog($"Pendências de assinatura: {pending}.");
            if (payload.TryGetProperty("debt_status", out var debtProp))
            {
                UpdateMinerDebtStatus(debtProp);
            }
        });

        _socketClient.OnAsync("miner_fine_quote", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out var errProp))
            {
                MinerFineStatus = $"Erro ao obter multa: {errProp.GetString()}";
                _minerFineRequestInFlight = false;
                _minerFineRequestSource = string.Empty;
                return;
            }

            var fineAmount = payload.TryGetProperty("fine_amount", out var fineProp) ? fineProp.GetInt32() : 0;
            var pendingTotal = payload.TryGetProperty("pending_total", out var pendingProp) ? pendingProp.GetInt32() : 0;
            if (payload.TryGetProperty("debt_status", out var debtProp))
            {
                UpdateMinerDebtStatus(debtProp);
            }

            if (fineAmount <= 0)
            {
                MinerFineStatus = "Nenhuma multa pendente.";
                _minerFineRequestInFlight = false;
                _minerFineRequestSource = string.Empty;
                return;
            }

            if (string.Equals(_minerFineRequestSource, "auto", StringComparison.OrdinalIgnoreCase))
            {
                if (MinerAutoPayFine && CanCoverFineAmount(fineAmount))
                {
                    await PayMinerFineAsync(fineAmount, pendingTotal, false);
                    return;
                }
                if (MinerFinePromise)
                {
                    await PayMinerFineAsync(fineAmount, pendingTotal, true);
                    return;
                }
                _minerFineRequestInFlight = false;
                _minerFineRequestSource = string.Empty;
                return;
            }

            if (string.Equals(_minerFineRequestSource, "manual", StringComparison.OrdinalIgnoreCase))
            {
                if (CanCoverFineAmount(fineAmount))
                {
                    await PayMinerFineAsync(fineAmount, pendingTotal, false);
                    return;
                }
                if (MinerFinePromise)
                {
                    await PayMinerFineAsync(fineAmount, pendingTotal, true);
                    return;
                }
                MinerFineStatus = "Saldo insuficiente para pagar a multa.";
                _minerFineRequestInFlight = false;
                _minerFineRequestSource = string.Empty;
                return;
            }

            MinerFineStatus = $"Multa pendente: {fineAmount} HPS.";
            _minerFineRequestInFlight = false;
            _minerFineRequestSource = string.Empty;
        });

        _socketClient.On("miner_fine_ack", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out var errProp))
            {
                MinerFineStatus = $"Erro ao pagar multa: {errProp.GetString()}";
                if (_pendingMinerFineVoucherIds.Count > 0)
                {
                    ReleaseLocalVouchers(_pendingMinerFineVoucherIds);
                    _pendingMinerFineVoucherIds = new List<string>();
                }
                _minerFineRequestInFlight = false;
                _minerFineRequestSource = string.Empty;
                return;
            }

            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                MinerFineStatus = "Falha ao pagar multa.";
                if (_pendingMinerFineVoucherIds.Count > 0)
                {
                    ReleaseLocalVouchers(_pendingMinerFineVoucherIds);
                    _pendingMinerFineVoucherIds = new List<string>();
                }
                _minerFineRequestInFlight = false;
                _minerFineRequestSource = string.Empty;
                return;
            }

            if (_pendingMinerFineVoucherIds.Count > 0)
            {
                _pendingMinerFineVoucherIds = new List<string>();
            }
            MinerFineStatus = "Multa paga com sucesso.";
            _minerFineRequestInFlight = false;
            _minerFineRequestSource = string.Empty;
            QueueAutomaticWalletRefresh();
        });

        _socketClient.On("miner_ban", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var reason = payload.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() : "Banido";
            HpsMiningStatus = "Mineracao bloqueada";
            AppendPowLog($"Mineracao bloqueada: {reason}");
        });

        _socketClient.On("hps_economy_status", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("multiplier", out var multProp))
            {
                ExchangeStatus = $"Multiplicador: {multProp.GetDouble():0.00}";
            }
            UpdatePowCostsFromPayload(payload);
        });

        _socketClient.On("price_settings", response =>
        {
            var payload = response.GetValue<JsonElement>();
            ApplyServerPriceSettings(payload);
            ServerPriceSettingsStatus = "Preços do servidor carregados.";
        });

        _socketClient.On("price_settings_ack", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errorProp) ? errorProp.GetString() ?? "Erro desconhecido" : "Erro desconhecido";
                ServerPriceSettingsStatus = $"Falha ao salvar preços: {error}";
                return;
            }

            ServerPriceSettingsStatus = "Preços do servidor atualizados.";
        });

        _socketClient.On("economy_report", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            if (payload.TryGetProperty("payload", out var reportPayload) && reportPayload.ValueKind == JsonValueKind.Object)
            {
				var issuer = reportPayload.TryGetProperty("issuer", out var issuerProp) ? issuerProp.GetString() ?? string.Empty : string.Empty;
                var totalMinted = reportPayload.TryGetProperty("total_minted", out var totalProp) ? totalProp.GetDouble() : 0.0;
                var multiplier = reportPayload.TryGetProperty("multiplier", out var multProp2) ? multProp2.GetDouble() : 1.0;
                var feeRate = reportPayload.TryGetProperty("exchange_fee_rate", out var feeProp2) ? feeProp2.GetDouble() : 0.0;
                var timestamp = reportPayload.TryGetProperty("timestamp", out var tsProp) ? tsProp.GetDouble() : 0.0;
                var updated = timestamp > 0 ? DateTimeOffset.FromUnixTimeSeconds((long)timestamp).ToLocalTime().ToString("HH:mm:ss") : string.Empty;

                if (!string.IsNullOrWhiteSpace(issuer))
                {
                    var existing = ExchangeServers.FirstOrDefault(s => string.Equals(s.Server, issuer, StringComparison.OrdinalIgnoreCase));
                    if (existing is null)
                    {
                        ExchangeServers.Add(new ExchangeServerStats
                        {
                            Server = issuer,
                            TotalMinted = $"{totalMinted:0.##}",
                            Multiplier = $"{multiplier:0.00}",
                            ExchangeFeeRate = $"{feeRate:0.000}",
                            UpdatedAt = updated
                        });
                    }
                    else
                    {
                        existing.TotalMinted = $"{totalMinted:0.##}";
                        existing.Multiplier = $"{multiplier:0.00}";
                        existing.ExchangeFeeRate = $"{feeRate:0.000}";
                        existing.UpdatedAt = updated;
                    }
                }
                UpdatePowCostsFromPayload(reportPayload);
            }

            ExchangeStatus = "Relatório econômico atualizado.";
        });

        _socketClient.On("phps_market", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("success", out var successProp) && !successProp.GetBoolean())
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() ?? "Erro desconhecido" : "Erro desconhecido";
                PhpsMarketStatus = "Falha ao carregar pHPS: " + error;
                return;
            }
            ApplyPhpsMarketPayload(payload);
        });

        _socketClient.On("issuer_recheck_result", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
            {
                IssuerRecheckStatus = payload.TryGetProperty("message", out var msgProp)
                    ? msgProp.GetString() ?? "Revogação enviada."
                    : "Revogação enviada.";
                return;
            }
            if (!(payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean()))
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() ?? "Erro desconhecido" : "Erro desconhecido";
                IssuerRecheckStatus = "Falha na revogação: " + error;
                ReleasePendingHpsPayment("issuer_recheck");
                return;
            }

            var status = payload.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? string.Empty : string.Empty;
            IssuerRecheckStatus = status switch
            {
                "confirmed" => "Autoria confirmada. A taxa foi devolvida pela custódia.",
                "timeout" => "Servidor emissor não respondeu. A exceção continua em custódia.",
                _ => "Checagem concluída."
            };
            ClearPendingHpsPayment("issuer_recheck");
            if (payload.TryGetProperty("market", out var marketProp) && marketProp.ValueKind == JsonValueKind.Object)
            {
                ApplyPhpsMarketPayload(marketProp);
            }
            _ = SearchContractsAsync();
        });

        _socketClient.On("issuer_verification_update", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var status = payload.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? string.Empty : string.Empty;
            var detail = payload.TryGetProperty("detail", out var detailProp) ? detailProp.GetString() ?? string.Empty : string.Empty;
            IssuerRecheckStatus = status switch
            {
                "confirmed" => "Checagem concluída: emissão confirmada.",
                "timeout" => "Checagem concluída: emissor indisponível, exceção mantida em custódia.",
                "failed" => string.IsNullOrWhiteSpace(detail) ? "Checagem falhou." : $"Checagem falhou: {detail}",
                _ => "Atualização de checagem recebida."
            };
            if (payload.TryGetProperty("market", out var marketProp) && marketProp.ValueKind == JsonValueKind.Object)
            {
                ApplyPhpsMarketPayload(marketProp);
            }
            _ = SearchContractsAsync();
        });

        _socketClient.On("phps_fund_result", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (!(payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean()))
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() ?? "Erro desconhecido" : "Erro desconhecido";
                PhpsMarketStatus = "Falha no aporte pHPS: " + error;
                return;
            }
            ApplyPhpsMarketPayload(payload);
            PhpsMarketStatus = "Aporte registrado com sucesso.";
            _ = RequestHpsWalletAsync();
            _ = SearchContractsAsync();
        });

        _socketClient.On("economy_contract_update", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var contractId = payload.TryGetProperty("contract_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            var reason = payload.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(contractId))
            {
                ExchangeStatus = string.IsNullOrWhiteSpace(reason)
                    ? $"Contrato econômico atualizado: {contractId}"
                    : $"Contrato econômico atualizado: {reason}";
                _ = _socketClient.EmitAsync("get_contract", new { contract_id = contractId });
                AppendPowLog($"Contrato econômico atualizado ({contractId}).");
            }
        });

        _socketClient.On("economy_alert", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var issuer = payload.TryGetProperty("issuer", out var issuerProp) ? issuerProp.GetString() ?? string.Empty : string.Empty;
            var reason = payload.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() ?? "economy_alert" : "economy_alert";
            if (!string.IsNullOrWhiteSpace(issuer))
            {
                ExchangeStatus = $"Alerta econômico: {issuer} ({reason})";
            }
        });

        _socketClient.On("hps_issuer_invalidated", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var issuer = payload.TryGetProperty("issuer", out var issuerProp) ? issuerProp.GetString() ?? string.Empty : string.Empty;
            var reason = payload.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() ?? "invalidated" : "invalidated";
            if (!string.IsNullOrWhiteSpace(issuer))
            {
                ExchangeStatus = $"Emissor invalidado: {issuer} ({reason})";
            }
        });

        _socketClient.On("exchange_quote", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
            {
                ExchangeQuoteMessage = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() ?? string.Empty : string.Empty;
                return;
            }

            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro no câmbio";
                ExchangeQuoteMessage = error ?? "Erro no câmbio";
                _pendingExchangeQuoteId = null;
                ClearPendingExchangeSourceVouchers();
                RaiseCommandCanExecuteChanged();
                return;
            }

            var quoteId = payload.TryGetProperty("quote_id", out var idProp) ? idProp.GetString() : null;
            var rate = payload.TryGetProperty("rate", out var rateProp) ? rateProp.GetDouble() : 1.0;
            var converted = payload.TryGetProperty("converted_value", out var convProp) ? convProp.GetInt32() : 0;
            var fee = payload.TryGetProperty("fee_amount", out var feeProp) ? feeProp.GetInt32() : 0;
            var receive = payload.TryGetProperty("receive_amount", out var recvProp) ? recvProp.GetInt32() : 0;

            _pendingExchangeQuoteId = quoteId;
            ExchangeQuoteMessage = $"Taxa: {rate:0.0000} | Convertido: {converted} | Taxa: {fee} | Receber: {receive}";
            RaiseCommandCanExecuteChanged();

            if (_owner is null || _exchangeConfirmPromptOpen || string.IsNullOrWhiteSpace(_pendingExchangeQuoteId))
            {
                return;
            }
            _exchangeConfirmPromptOpen = true;
            _ = ShowExchangeConfirmPromptAsync(rate, converted, fee, receive);
        });

        _socketClient.On("exchange_complete", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro no câmbio";
                var failedTransferId = payload.TryGetProperty("transfer_id", out var failedTransferIdProp) ? failedTransferIdProp.GetString() ?? string.Empty : string.Empty;
                ExchangeStatus = error ?? "Erro no câmbio";
                TransferStatus = string.IsNullOrWhiteSpace(error) ? "Falha no câmbio." : $"Falha no câmbio: {error}";
                if (!string.IsNullOrWhiteSpace(_pendingExchangeTransferId))
                {
                    _transferStatusCache[_pendingExchangeTransferId] = "rejected";
                }
                if (!string.IsNullOrWhiteSpace(failedTransferId))
                {
                    UpdateFlowPopupStatus(TransferFlowPopupId(failedTransferId, "signature"), $"Falha na assinatura: {error}");
                    MarkFlowPopupDone(TransferFlowPopupId(failedTransferId, "signature"));
                    _submittedMinerTransferAt.TryRemove(failedTransferId, out _);
                }
                _pendingExchangeTransferId = null;
                _pendingExchangeVoucherId = null;
                _pendingExchangeQuoteId = null;
                ClearPendingExchangeSourceVouchers();
                ResetExchangePendingRefreshState();
                RaiseCommandCanExecuteChanged();
                if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
                return;
            }

            var stage = payload.TryGetProperty("stage", out var stageProp) ? stageProp.GetString() ?? "initiated" : "initiated";
            var transferId = payload.TryGetProperty("transfer_id", out var transferIdProp) ? transferIdProp.GetString() ?? string.Empty : string.Empty;
            var newVoucherId = payload.TryGetProperty("new_voucher_id", out var newVoucherProp) ? newVoucherProp.GetString() ?? string.Empty : string.Empty;
            if (payload.TryGetProperty("voucher_offer", out var voucherOfferProp) && voucherOfferProp.ValueKind == JsonValueKind.Object)
            {
                _ = HandleVoucherOfferAsync(voucherOfferProp.Clone());
            }

            if (string.Equals(stage, "finalized", StringComparison.OrdinalIgnoreCase))
            {
                ExchangeStatus = "Câmbio concluído.";
                TransferStatus = "Transferência concluída.";
                var popupId = TransferFlowPopupId(transferId, "monitor");
                if (!string.IsNullOrWhiteSpace(transferId))
                {
                    _completedTransferIds.Add(transferId);
                    _transferStatusCache[transferId] = "completed";
                }
                var details = string.IsNullOrWhiteSpace(transferId) ? "Transferência finalizada." : $"Transferência: {transferId}";
                StartFlowPopup(popupId, "Transferência em andamento", "Status: Transferência concluída", details);
                if (!string.IsNullOrWhiteSpace(transferId))
                {
                    AppendFlowPopupLog(popupId, $"Transferência {transferId}: concluída.");
                    UpdateFlowPopupStatus(TransferFlowPopupId(transferId, "signature"), $"Assinatura concluída para {transferId}.");
                    MarkFlowPopupDone(TransferFlowPopupId(transferId, "signature"));
                    _submittedMinerTransferAt.TryRemove(transferId, out _);
                }
                ResetExchangePendingRefreshState();
                MarkFlowPopupDone(popupId);
                QueueAutomaticPendingTransfersRefresh(includeMiner: true);
                GhostPendingExchangeSourceVouchers();
                _pendingExchangeTransferId = null;
                _pendingExchangeVoucherId = null;
                _pendingExchangeQuoteId = null;
                UpdateAutomaticStateSyncLoop();
                RaiseCommandCanExecuteChanged();
                return;
            }

            HandleExchangePendingState(transferId, newVoucherId);
        });

        _socketClient.On("exchange_pending", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Câmbio pendente falhou";
                ExchangeStatus = error ?? "Câmbio pendente falhou";
                return;
            }
            var transferId = payload.TryGetProperty("transfer_id", out var transferIdProp) ? transferIdProp.GetString() ?? string.Empty : string.Empty;
            var newVoucherId = payload.TryGetProperty("new_voucher_id", out var newVoucherProp) ? newVoucherProp.GetString() ?? string.Empty : string.Empty;
            var status = payload.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? string.Empty : string.Empty;
            var miner = payload.TryGetProperty("assigned_miner", out var minerProp) ? minerProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(transferId))
            {
                if (!string.IsNullOrWhiteSpace(status))
                {
                    _transferStatusCache[transferId] = status;
                }
                if (!string.IsNullOrWhiteSpace(miner))
                {
                    _transferMinerCache[transferId] = miner;
                }
            }
            HandleExchangePendingState(transferId, newVoucherId);
        });

        _socketClient.On("voucher_audit", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var requestId = payload.TryGetProperty("request_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(requestId) && _voucherAuditWaiters.TryGetValue(requestId, out var waiter))
            {
                var entries = new List<VoucherAuditEntry>();
                if (payload.TryGetProperty("vouchers", out var vouchersProp) && vouchersProp.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in vouchersProp.EnumerateArray())
                    {
                        entries.Add(new VoucherAuditEntry(item.GetRawText()));
                    }
                }
                waiter.TrySetResult(entries);
                _voucherAuditWaiters.Remove(requestId);
            }
            if (!string.IsNullOrWhiteSpace(_pendingVoucherAuditRequestId) &&
                !string.IsNullOrWhiteSpace(requestId) &&
                !string.Equals(_pendingVoucherAuditRequestId, requestId, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            if (payload.TryGetProperty("error", out var errProp))
            {
                VoucherAuditSummary = $"Erro na análise: {errProp.GetString()}";
                return;
            }

            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                VoucherAuditSummary = "Falha ao analisar vouchers.";
                return;
            }

            if (!payload.TryGetProperty("vouchers", out var vouchersListProp) || vouchersListProp.ValueKind != JsonValueKind.Array)
            {
                VoucherAuditSummary = "Nenhum voucher encontrado.";
                VoucherAuditDetails = string.Empty;
                return;
            }

            var total = vouchersListProp.GetArrayLength();
            var invalidated = 0;
            foreach (var voucherElem in vouchersListProp.EnumerateArray())
            {
                if (voucherElem.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }
                if (voucherElem.TryGetProperty("invalidated", out var invProp) && invProp.ValueKind == JsonValueKind.True)
                {
                    invalidated++;
                }
            }

            VoucherAuditSummary = $"Vouchers analisados: {total}. Invalidos: {invalidated}.";
            VoucherAuditDetails = FormatJson(vouchersListProp);
            _pendingVoucherAuditRequestId = null;
        });

        _socketClient.On("exchange_trace", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var requestId = payload.TryGetProperty("request_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(requestId) && _exchangeTraceWaiters.TryGetValue(requestId, out var waiter))
            {
                var entries = new List<ExchangeTraceEntry>();
                if (payload.TryGetProperty("traces", out var tracesProp) && tracesProp.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in tracesProp.EnumerateArray())
                    {
                        entries.Add(new ExchangeTraceEntry(item.GetRawText()));
                    }
                }
                waiter.TrySetResult(entries);
                _exchangeTraceWaiters.Remove(requestId);
            }
            if (!string.IsNullOrWhiteSpace(_pendingSpendAuditRequestId) &&
                !string.IsNullOrWhiteSpace(requestId) &&
                !string.Equals(_pendingSpendAuditRequestId, requestId, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            if (payload.TryGetProperty("error", out var errProp))
            {
                SpendAuditSummary = $"Erro na análise: {errProp.GetString()}";
                return;
            }

            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                SpendAuditSummary = "Falha ao analisar gastos.";
                return;
            }

            if (!payload.TryGetProperty("traces", out var tracesListProp) || tracesListProp.ValueKind != JsonValueKind.Array)
            {
                SpendAuditSummary = "Nenhum gasto encontrado.";
                SpendAuditDetails = string.Empty;
                return;
            }

            SpendAuditSummary = $"Gastos analisados: {tracesListProp.GetArrayLength()}.";
            SpendAuditDetails = FormatJson(tracesListProp);
            _pendingSpendAuditRequestId = null;
        });

        _socketClient.OnAsync("api_app_versions", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var requestId = payload.TryGetProperty("request_id", out var reqProp) ? reqProp.GetString() : null;
            if (string.IsNullOrWhiteSpace(requestId) || !_pendingApiAppRequests.TryGetValue(requestId, out var request))
            {
                return;
            }
            _pendingApiAppRequests.Remove(requestId);

            var hasError = payload.TryGetProperty("error", out var apiErrProp);
            if ((payload.TryGetProperty("success", out var successProp) && !successProp.GetBoolean()) || hasError)
            {
                var errorText = hasError && apiErrProp.ValueKind == JsonValueKind.String ? apiErrProp.GetString() : "erro desconhecido";
                BrowserContent = $"API App: falha ao buscar versões: {errorText}";
                RenderContentFallback(request.ContentInfo, request.ContentBytes, request.CurrentHash, request.MimeType);
                return;
            }

            if (!payload.TryGetProperty("versions", out var versionsProp) || versionsProp.ValueKind != JsonValueKind.Array)
            {
                RenderContentFallback(request.ContentInfo, request.ContentBytes, request.CurrentHash, request.MimeType);
                return;
            }

            var latestHash = payload.TryGetProperty("latest_hash", out var latestProp) ? latestProp.GetString() ?? string.Empty : string.Empty;
            var appName = request.AppName;
            var versions = new List<ApiAppVersionInfo>();
            foreach (var versionElem in versionsProp.EnumerateArray())
            {
                if (versionElem.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }
                var hash = versionElem.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty;
                if (string.IsNullOrWhiteSpace(hash))
                {
                    continue;
                }
                var versionApp = versionElem.TryGetProperty("app_name", out var appProp) ? appProp.GetString() ?? string.Empty : string.Empty;
                if (string.IsNullOrWhiteSpace(appName))
                {
                    appName = versionApp;
                }
                var username = versionElem.TryGetProperty("username", out var userProp) ? userProp.GetString() ?? string.Empty : string.Empty;
                var label = versionElem.TryGetProperty("version_label", out var labelProp) ? labelProp.GetString() ?? string.Empty : string.Empty;
                var ts = versionElem.TryGetProperty("timestamp", out var tsProp) ? tsProp.GetDouble() : 0.0;
                var tsText = ts > 0
                    ? DateTimeOffset.FromUnixTimeSeconds((long)ts).ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                    : string.Empty;
                versions.Add(new ApiAppVersionInfo
                {
                    AppName = versionApp,
                    ContentHash = hash,
                    Username = username,
                    VersionLabel = string.IsNullOrWhiteSpace(label) ? "Upload" : label,
                    TimestampText = tsText,
                    IsLatest = string.Equals(hash, latestHash, StringComparison.OrdinalIgnoreCase),
                    IsCurrent = string.Equals(hash, request.CurrentHash, StringComparison.OrdinalIgnoreCase)
                });
            }

            if (versions.Count == 0)
            {
                BrowserContent = "API App: nenhuma versão disponível.";
                RenderContentFallback(request.ContentInfo, request.ContentBytes, request.CurrentHash, request.MimeType);
                return;
            }

            if (_owner is null)
            {
                RenderContentFallback(request.ContentInfo, request.ContentBytes, request.CurrentHash, request.MimeType);
                return;
            }

            var window = new ApiAppVersionsWindow();
            window.SetContent(appName, versions, request.CurrentHash, latestHash);
            var result = await window.ShowDialog<ApiAppVersionsDialogResult>(_owner);
            if (result is null)
            {
                RenderContentFallback(request.ContentInfo, request.ContentBytes, request.CurrentHash, request.MimeType);
                return;
            }

            if (!string.IsNullOrWhiteSpace(result.SelectedHash))
            {
                var url = $"hps://{result.SelectedHash}";
                BrowserUrl = url;
                AddToHistory(url);
                _apiAppBypassHashes.Add(result.SelectedHash);
                await RequestContentByHashAsync(result.SelectedHash);
                return;
            }

            if (result.ProceedCurrent && !string.IsNullOrWhiteSpace(request.CurrentHash))
            {
                var url = $"hps://{request.CurrentHash}";
                BrowserUrl = url;
                AddToHistory(url);
                _apiAppBypassHashes.Add(request.CurrentHash);
                await RequestContentByHashAsync(request.CurrentHash);
                return;
            }

            RenderContentFallback(request.ContentInfo, request.ContentBytes, request.CurrentHash, request.MimeType);
        });

        _socketClient.On("miner_signature_request", response =>
        {
            var payload = response.GetValue<JsonElement>();
            UpsertPendingMinerTransfer(payload, true);
        });

        _socketClient.OnAsync("miner_issuer_verification_request", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            await ProcessIssuerVerificationJobAsync(payload);
        });

        _socketClient.On("miner_pending_transfers", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success || !payload.TryGetProperty("transfers", out var transfersProp) || transfersProp.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            var pendingIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var transferElem in transfersProp.EnumerateArray())
            {
                var transferId = UpsertPendingMinerTransfer(transferElem, false);
                if (!string.IsNullOrWhiteSpace(transferId))
                {
                    pendingIds.Add(transferId);
                }
            }

            foreach (var staleId in _pendingMinerTransfers.Keys.Where(id => !pendingIds.Contains(id)).ToList())
            {
                _pendingMinerTransfers.TryRemove(staleId, out _);
                var popupId = TransferFlowPopupId(staleId, "signature");
                if (_submittedMinerTransferAt.ContainsKey(staleId))
                {
                    UpdateFlowPopupStatus(popupId, $"Assinatura recebida pelo servidor para {staleId}. Processando.");
                }
                else
                {
                    UpdateFlowPopupStatus(popupId, $"Assinatura concluída para {staleId}.");
                    MarkFlowPopupDone(popupId);
                }
            }

            MinerPendingSignatures = pendingIds.Count.ToString();
            UpdateAutomaticStateSyncLoop();
            RaiseCommandCanExecuteChanged();
        });

        _socketClient.On("miner_signature_ack", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            var pending = payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean();
            var transferId = payload.TryGetProperty("transfer_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(transferId) && !pending)
            {
                _pendingMinerTransfers.TryRemove(transferId, out _);
                _submittedMinerTransferAt.TryRemove(transferId, out _);
                lock (_pendingInvalidationTransfers)
                {
                    _pendingInvalidationTransfers.Remove(transferId);
                }
                MarkFlowPopupDone(TransferFlowPopupId(transferId, "signature"));
                UpdateAutomaticStateSyncLoop();
                RaiseCommandCanExecuteChanged();
            }
            if (payload.TryGetProperty("debt_status", out var debtProp))
            {
                UpdateMinerDebtStatus(debtProp);
            }
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() ?? string.Empty : string.Empty;
                AppendPowLog($"Falha na assinatura: {error}");
                if (!string.IsNullOrWhiteSpace(transferId))
                {
                    UpdateFlowPopupStatus(TransferFlowPopupId(transferId, "signature"), $"Falha na assinatura: {error}");
                }
            }
            else
            {
                var message = payload.TryGetProperty("message", out var messageProp) ? messageProp.GetString() ?? string.Empty : string.Empty;
                if (pending)
                {
                    AppendPowLog(string.IsNullOrWhiteSpace(message)
                        ? $"Assinatura recebida pelo servidor para transferência {transferId}. Processando."
                        : message);
                }
                else
                {
                    AppendPowLog($"Assinatura enviada para transferência {transferId}.");
                }
                if (!string.IsNullOrWhiteSpace(transferId))
                {
                    UpdateFlowPopupStatus(
                        TransferFlowPopupId(transferId, "signature"),
                        pending
                            ? $"Assinatura recebida pelo servidor para {transferId}. Processando."
                            : $"Assinatura enviada para {transferId}.");
                    if (!pending)
                    {
                        MarkFlowPopupDone(TransferFlowPopupId(transferId, "signature"));
                    }
                }
            }
            _ = Task.Run(TryRunDeferredAutoSignAsync);
        });

        _socketClient.On("contracts_results", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var responseRequestId = payload.TryGetProperty("request_id", out var requestProp) ? requestProp.GetString() ?? string.Empty : string.Empty;
            if (int.TryParse(responseRequestId, NumberStyles.Integer, CultureInfo.InvariantCulture, out var responseVersion) &&
                responseVersion != Volatile.Read(ref _contractSearchRequestVersion))
            {
                return;
            }
            if (payload.TryGetProperty("error", out _))
            {
                var errorText = payload.TryGetProperty("error", out var errorProp) ? errorProp.GetString() ?? "erro" : "erro";
                ContractDetailsText = $"Falha ao buscar contratos: {errorText}";
                _contractLoadingPage = false;
                RaiseCommandCanExecuteChanged();
                return;
            }

            if (!payload.TryGetProperty("contracts", out var contractsProp) || contractsProp.ValueKind != JsonValueKind.Array)
            {
                _contractLoadingPage = false;
                RaiseCommandCanExecuteChanged();
                return;
            }

            _contractServerTotalCount = payload.TryGetProperty("total", out var totalProp) && totalProp.ValueKind == JsonValueKind.Number
                ? Math.Max(contractsProp.GetArrayLength(), totalProp.GetInt32())
                : contractsProp.GetArrayLength();

            _contractFetchedResults.Clear();
            foreach (var contractElem in contractsProp.EnumerateArray())
            {
                var contract = ParseContract(contractElem);
                if (contract is not null)
                {
                    _contractFetchedResults.Add(contract);
                    _database.SaveContractRecord(contract);
                }
            }

            ApplyContractSearchFilterAndSort();
            RenderContractsCurrentPage();
            _contractLoadingPage = false;
            RaiseCommandCanExecuteChanged();
        });

        _socketClient.On("contract_details", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out _))
            {
                return;
            }

            if (!payload.TryGetProperty("contract", out var contractProp) || contractProp.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            var contract = ParseContract(contractProp);
            if (contract is null)
            {
                return;
            }

            var existingFetched = _contractFetchedResults.FirstOrDefault(c => c.ContractId == contract.ContractId);
            if (existingFetched is not null)
            {
                existingFetched.ContractContent = contract.ContractContent;
                existingFetched.ContractTitle = contract.ContractTitle;
                existingFetched.Signature = contract.Signature;
                existingFetched.Verified = contract.Verified;
                existingFetched.IntegrityOk = contract.IntegrityOk;
                existingFetched.ViolationReason = contract.ViolationReason;
                existingFetched.IsContractViolation = contract.IsContractViolation;
                _database.SaveContractRecord(existingFetched);
            }
            else
            {
                _contractFetchedResults.Add(contract);
                _database.SaveContractRecord(contract);
                ApplyContractSearchFilterAndSort();
                _contractServerTotalCount = Math.Max(_contractServerTotalCount, _contractFetchedResults.Count);
            }

            var existing = Contracts.FirstOrDefault(c => c.ContractId == contract.ContractId);
            if (existing is not null)
            {
                existing.ContractContent = contract.ContractContent;
                existing.ContractTitle = contract.ContractTitle;
                existing.Signature = contract.Signature;
                existing.Verified = contract.Verified;
                existing.IntegrityOk = contract.IntegrityOk;
                existing.ViolationReason = contract.ViolationReason;
                existing.IsContractViolation = contract.IsContractViolation;
                _database.SaveContractRecord(existing);
            }

            if (SelectedContract is not null && SelectedContract.ContractId == contract.ContractId)
            {
                ContractDetailsText = BuildContractDetails(contract);
            }
            ScheduleClientPropagationSync();
            UpdateContractPendingFlags();
            UpdateContractViolationFlags(contract.ViolationReason);
            if (contract.IsContractViolation && !string.IsNullOrWhiteSpace(contract.ViolationReason))
            {
                StartContractAlert("Contrato adulterado ou inválido detectado.");
            }
        });

        _socketClient.On("pending_transfers", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out _))
            {
                return;
            }

            if (!payload.TryGetProperty("transfers", out var transfersProp) || transfersProp.ValueKind != JsonValueKind.Array)
            {
                PendingTransfersCount = 0;
                PendingTransferStatus = string.Empty;
                _pendingTransfersByContract.Clear();
                PendingTransfers.Clear();
                SelectedPendingTransfer = null;
                _pendingTransferId = null;
                _pendingTransferType = null;
                RaiseCommandCanExecuteChanged();
                return;
            }

            var count = transfersProp.GetArrayLength();
            PendingTransfersCount = count;
            PendingTransferStatus = count > 0
                ? $"Você tem {count} pendência(s) contratual(is)."
                : string.Empty;
            if (count == 0)
            {
                if (!string.IsNullOrWhiteSpace(_pendingExchangeTransferId))
                {
                    FinalizeExchangePendingState(_pendingExchangeTransferId, "completed", _pendingExchangeVoucherId ?? string.Empty);
                }
                _pendingTransfersByContract.Clear();
                PendingTransfers.Clear();
                SelectedPendingTransfer = null;
                _pendingTransferId = null;
                _pendingTransferType = null;
                RaiseCommandCanExecuteChanged();
            }

            _pendingTransfersByContract.Clear();
            PendingTransfers.Clear();
            if (count > 0)
            {
                var first = transfersProp.EnumerateArray().FirstOrDefault();
                if (first.ValueKind == JsonValueKind.Object)
                {
                    _pendingTransferId = first.TryGetProperty("transfer_id", out var idProp) ? idProp.GetString() : null;
                    _pendingTransferType = first.TryGetProperty("transfer_type", out var typeProp) ? typeProp.GetString() : null;
                    RaiseCommandCanExecuteChanged();
                }
            }

            foreach (var transferElem in transfersProp.EnumerateArray())
            {
                if (transferElem.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }
                var contractId = transferElem.TryGetProperty("contract_id", out var contractProp) ? contractProp.GetString() ?? string.Empty : string.Empty;
                var transferId = transferElem.TryGetProperty("transfer_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
                var transferInfo = new PendingTransferInfo(
                    transferId,
                    transferElem.TryGetProperty("transfer_type", out var typeProp) ? typeProp.GetString() ?? string.Empty : string.Empty,
                    transferElem.TryGetProperty("original_owner", out var ownerProp) ? ownerProp.GetString() ?? string.Empty : string.Empty,
                    transferElem.TryGetProperty("target_user", out var targetProp) ? targetProp.GetString() ?? string.Empty : string.Empty,
                    transferElem.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty,
                    transferElem.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() ?? string.Empty : string.Empty,
                    transferElem.TryGetProperty("app_name", out var appProp) ? appProp.GetString() ?? string.Empty : string.Empty
                );
                if (!string.IsNullOrWhiteSpace(contractId))
                {
                    _pendingTransfersByContract[contractId] = transferInfo;
                }
                PendingTransfers.Add(transferInfo);
            }

            if (!string.IsNullOrWhiteSpace(_pendingExchangeTransferId) &&
                !PendingTransfers.Any(p => string.Equals(p.TransferId, _pendingExchangeTransferId, StringComparison.OrdinalIgnoreCase)))
            {
                var pendingStatus = _transferStatusCache.TryGetValue(_pendingExchangeTransferId, out var cachedStatus)
                    ? cachedStatus
                    : "completed";
                if (IsTransferFinalStatus(pendingStatus.Trim().ToLowerInvariant()))
                {
                    FinalizeExchangePendingState(_pendingExchangeTransferId, pendingStatus, _pendingExchangeVoucherId ?? string.Empty);
                }
            }

            if (PendingTransfers.Count > 0)
            {
                SelectedPendingTransfer = PendingTransfers[0];
            }

            UpdateContractPendingFlags();
            if (count > 0)
            {
                StartContractAlert($"Você está com {count} pendência(s) contratual(is).");
            }
            else if (_contractViolations.Count == 0)
            {
                StopContractAlert();
            }
        });

        _socketClient.On("monetary_transfer_pending", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var transferId = payload.TryGetProperty("transfer_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(transferId))
            {
                return;
            }
            var transferType = payload.TryGetProperty("transfer_type", out var typeProp) ? typeProp.GetString() ?? string.Empty : string.Empty;
            var sender = payload.TryGetProperty("sender", out var senderProp) ? senderProp.GetString() ?? string.Empty : string.Empty;
            var receiver = payload.TryGetProperty("receiver", out var receiverProp) ? receiverProp.GetString() ?? string.Empty : string.Empty;
            var miner = payload.TryGetProperty("assigned_miner", out var minerProp) ? minerProp.GetString() ?? string.Empty : string.Empty;
            var status = payload.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? string.Empty : string.Empty;
            var spendHpsActionType = GetActionTypeFromSpendHpsTransfer(transferType);
            if (!string.IsNullOrWhiteSpace(spendHpsActionType))
            {
                MovePendingHpsPaymentToWalletSync(spendHpsActionType);
            }
            var (mergedStatus, mergedMiner) = MergeTransferSnapshot(transferId, status, miner);
            if (string.Equals(transferType, "exchange_in", StringComparison.OrdinalIgnoreCase))
            {
                var newVoucherId = payload.TryGetProperty("new_voucher_id", out var voucherProp) ? voucherProp.GetString() ?? string.Empty : string.Empty;
                HandleExchangePendingState(transferId, newVoucherId);
                return;
            }
            var details = $"Transferência: {transferId}\nRemetente: {sender}\nDestinatário: {receiver}\nMinerador: {mergedMiner}";
            var statusLabel = DescribeTransferStatus(mergedStatus, string.Empty);
            var popupId = TransferFlowPopupId(transferId, "monitor");
            StartFlowPopup(popupId, "Transferência em andamento", $"Status: {statusLabel}", details);
            AppendFlowPopupLog(popupId, $"Minerador: {mergedMiner}");
        });

        _socketClient.On("monetary_transfer_update", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var transferId = payload.TryGetProperty("transfer_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            var status = payload.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? string.Empty : string.Empty;
            var reason = payload.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(status))
            {
                return;
            }
            if (!string.IsNullOrWhiteSpace(transferId) &&
                _completedTransferIds.Contains(transferId) &&
                !string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(status, "signed", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            var miner = payload.TryGetProperty("assigned_miner", out var minerProp) ? minerProp.GetString() ?? string.Empty : string.Empty;
            var (mergedStatus, _) = MergeTransferSnapshot(transferId, status, miner);
            if (!string.IsNullOrWhiteSpace(transferId) &&
                string.Equals(transferId, _pendingExchangeTransferId, StringComparison.OrdinalIgnoreCase) &&
                IsTransferFinalStatus(mergedStatus.Trim().ToLowerInvariant()))
            {
                var newVoucherId = payload.TryGetProperty("new_voucher_id", out var voucherProp) ? voucherProp.GetString() ?? string.Empty : string.Empty;
                FinalizeExchangePendingState(transferId, mergedStatus, newVoucherId);
            }
            var label = DescribeTransferStatus(mergedStatus, reason);
            TransferStatus = label;
            var popupId = TransferFlowPopupId(transferId, "monitor");
            var details = string.IsNullOrWhiteSpace(transferId) ? "Atualização recebida." : $"Transferência: {transferId}";
            StartFlowPopup(popupId, "Transferência em andamento", $"Status: {label}", details);
            AppendFlowPopupLog(popupId, $"Transferência {transferId}: {label}");
            if (IsTransferFinalStatus(mergedStatus))
            {
                if (!string.IsNullOrWhiteSpace(transferId))
                {
                    if (string.Equals(mergedStatus, "completed", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(mergedStatus, "signed", StringComparison.OrdinalIgnoreCase))
                    {
                        _completedTransferIds.Add(transferId);
                    }
                    _transferStatusCache.Remove(transferId);
                    _transferMinerCache.Remove(transferId);
                    UpdateFlowPopupStatus(TransferFlowPopupId(transferId, "signature"), $"Assinatura concluída para {transferId}.");
                    MarkFlowPopupDone(TransferFlowPopupId(transferId, "signature"));
                    _submittedMinerTransferAt.TryRemove(transferId, out _);
                }
                MarkFlowPopupDone(popupId);
            }
        });

        _socketClient.On("pending_transfer_notice", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var count = payload.TryGetProperty("count", out var countProp) ? countProp.GetInt32() : 1;
            PendingTransfersCount = count;
            PendingTransferStatus = count > 0
                ? $"Você tem {count} pendência(s) contratual(is)."
                : string.Empty;
            if (count > 0)
            {
                StartContractAlert($"Você está com {count} pendência(s) contratual(is).");
            }
            else
            {
                _pendingTransfersByContract.Clear();
                PendingTransfers.Clear();
                SelectedPendingTransfer = null;
                _pendingTransferId = null;
                _pendingTransferType = null;
                RaiseCommandCanExecuteChanged();
                if (_contractViolations.Count == 0)
                {
                    StopContractAlert();
                }
            }
        });

        _socketClient.On("contract_violation_notice", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var violationType = payload.TryGetProperty("violation_type", out var typeProp) ? typeProp.GetString() ?? string.Empty : string.Empty;
            var contentHash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty;
            var domain = payload.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() ?? string.Empty : string.Empty;
            var reason = payload.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() ?? "contract_violation" : "contract_violation";
            if (string.Equals(violationType, "domain", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(domain))
            {
                RegisterContractViolation("domain", domain, reason);
            }
            else if (!string.IsNullOrWhiteSpace(contentHash))
            {
                RegisterContractViolation("content", contentHash, reason);
            }
            StartContractAlert("Você está com pendências contratuais.");
        });

        _socketClient.On("contract_violation_cleared", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var violationType = payload.TryGetProperty("violation_type", out var typeProp) ? typeProp.GetString() ?? string.Empty : string.Empty;
            var contentHash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty;
            var domain = payload.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() ?? string.Empty : string.Empty;
            if (string.Equals(violationType, "domain", StringComparison.OrdinalIgnoreCase))
            {
                ClearContractViolation("domain", domain);
                DismissCriticalBrowserErrorForTarget("domain", domain);
            }
            else
            {
                ClearContractViolation("content", contentHash);
                DismissCriticalBrowserErrorForTarget("content", contentHash);
            }
        });

        _socketClient.OnAsync("content_repair_payload", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out var errProp))
            {
                TransferStatus = $"Falha ao preparar reparo: {errProp.GetString()}";
                return;
            }
            if (!payload.TryGetProperty("content_hash", out var hashProp))
            {
                TransferStatus = "Reparo inválido: hash ausente.";
                return;
            }
            if (_owner is null)
            {
                TransferStatus = "Reparo indisponível: janela principal não definida.";
                return;
            }
            var contentHash = hashProp.GetString() ?? string.Empty;
            var title = payload.TryGetProperty("title", out var titleProp) ? titleProp.GetString() ?? string.Empty : string.Empty;
            var description = payload.TryGetProperty("description", out var descProp) ? descProp.GetString() ?? string.Empty : string.Empty;
            var mime = payload.TryGetProperty("mime_type", out var mimeProp) ? mimeProp.GetString() ?? "application/octet-stream" : "application/octet-stream";

            var path = await _fileDialogService.OpenFileAsync(_owner, "Selecionar arquivo original", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                TransferStatus = "Reparo cancelado.";
                return;
            }
            var content = await File.ReadAllBytesAsync(path);
            var computed = _contentService.ComputeSha256HexBytes(content);
            if (!string.Equals(computed, contentHash, StringComparison.OrdinalIgnoreCase))
            {
                TransferStatus = "Arquivo não corresponde ao hash original.";
                return;
            }
            TransferStatus = "Enviando reparo de conteúdo...";
            await UploadContentBytesAsync(title, description, mime, content, contentHash);
        });

        _socketClient.OnAsync("miner_selector_request", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var transferId = payload.TryGetProperty("transfer_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            var serverCommit = payload.TryGetProperty("selector_commit", out var commitProp) ? commitProp.GetString() ?? string.Empty : string.Empty;
            var minerListHash = payload.TryGetProperty("miner_list_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(transferId) || string.IsNullOrWhiteSpace(serverCommit))
            {
                return;
            }
            if (!payload.TryGetProperty("miner_list", out var minersProp) || minersProp.ValueKind != JsonValueKind.Array)
            {
                await _socketClient.EmitAsync("miner_selector_response", new { transfer_id = transferId, accept = false });
                AppendImportantFlowLog($"Transferência {transferId}: lista de mineradores ausente; seleção recusada.");
                return;
            }
            var miners = minersProp.EnumerateArray()
                .Select(m => m.GetString())
                .Where(m => !string.IsNullOrWhiteSpace(m))
                .Select(m => m!)
                .ToList();
            if (miners.Count == 0)
            {
                await _socketClient.EmitAsync("miner_selector_response", new { transfer_id = transferId, accept = false });
                AppendImportantFlowLog($"Transferência {transferId}: lista de mineradores vazia; seleção recusada.");
                return;
            }
            var recomputedHash = ComputeSha256Hex(JsonSerializer.Serialize(miners));
            if (!string.IsNullOrWhiteSpace(minerListHash) && !string.Equals(minerListHash, recomputedHash, StringComparison.OrdinalIgnoreCase))
            {
                await _socketClient.EmitAsync("miner_selector_response", new { transfer_id = transferId, accept = false });
                AppendImportantFlowLog($"Transferência {transferId}: hash de mineradores inválido; seleção recusada.");
                return;
            }

            var reward = payload.TryGetProperty("reward", out var rewardProp) ? rewardProp.GetInt32() : 0;
            var reputationBonus = payload.TryGetProperty("reputation_bonus", out var repProp) ? repProp.GetInt32() : 0;
            var accepted = false;
            if (AutoAcceptMinerSelection)
            {
                accepted = true;
            }
            else
            {
                if (_owner is null)
                {
                    await _socketClient.EmitAsync("miner_selector_response", new { transfer_id = transferId, accept = false });
                    AppendImportantFlowLog($"Transferência {transferId}: janela indisponível para confirmar seleção; recusado.");
                    return;
                }
                var message = $"O servidor solicita que você selecione um minerador de forma aleatória para a transação {transferId}.\n" +
                              $"Recompensa: {reward} HPS e +{reputationBonus} de reputação.\n\nDeseja prosseguir?";
                accepted = await _promptService.ConfirmAsync(_owner, "Seleção de Minerador", message, "Aceitar", "Recusar");
            }
            if (!accepted)
            {
                await _socketClient.EmitAsync("miner_selector_response", new { transfer_id = transferId, accept = false });
                return;
            }

            var clientNonce = GenerateNonceHex(32);
            _pendingMinerSelections[transferId] = new PendingMinerSelection(
                clientNonce,
                miners,
                minerListHash,
                serverCommit
            );
            var clientCommit = ComputeSha256Hex(clientNonce);
            await _socketClient.EmitAsync("miner_selector_response", new
            {
                transfer_id = transferId,
                accept = true,
                client_commit = clientCommit
            });
            TransferStatus = "Commit de seleção enviado.";
            AppendImportantFlowLog($"Transferência {transferId}: commit de seleção enviado.");
        });

        _socketClient.OnAsync("miner_selector_reveal", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var transferId = payload.TryGetProperty("transfer_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            var serverNonce = payload.TryGetProperty("server_nonce", out var nonceProp) ? nonceProp.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(transferId) || string.IsNullOrWhiteSpace(serverNonce))
            {
                return;
            }
            if (!_pendingMinerSelections.TryGetValue(transferId, out var pending))
            {
                return;
            }
            var serverCommit = ComputeSha256Hex(serverNonce);
            if (!string.Equals(serverCommit, pending.ServerCommit, StringComparison.OrdinalIgnoreCase))
            {
                AppendPowLog($"Commit do servidor inválido para {transferId}.");
                return;
            }
            var seedBytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{serverNonce}:{pending.ClientNonce}:{transferId}"));
            var index = (int)(BinaryPrimitives.ReadUInt64BigEndian(seedBytes.AsSpan(0, 8)) % (ulong)pending.Miners.Count);
            var selectedMiner = pending.Miners[index];
            var seedHex = Convert.ToHexString(seedBytes).ToLowerInvariant();
            var selectorContractB64 = string.Empty;
            if (_privateKey is not null && !string.IsNullOrWhiteSpace(User))
            {
                var selectorDetails = new Dictionary<string, string>
                {
                    { "TRANSFER_ID", transferId },
                    { "SELECTED_MINER", selectedMiner },
                    { "CLIENT_NONCE", pending.ClientNonce },
                    { "SERVER_COMMIT", pending.ServerCommit },
                    { "MINER_LIST_HASH", pending.MinerListHash },
                    { "SEED", seedHex }
                };
                var selectorTemplate = _contentService.BuildContractTemplate("miner_selector_client_choice", selectorDetails);
                var selectorContract = _contentService.ApplyContractSignature(selectorTemplate, _privateKey, User);
                selectorContractB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(selectorContract));
            }

            await _socketClient.EmitAsync("miner_selector_reveal_response", new
            {
                transfer_id = transferId,
                client_nonce = pending.ClientNonce,
                selected_miner = selectedMiner,
                miner_list_hash = pending.MinerListHash,
                seed = seedHex,
                selector_contract_content = selectorContractB64
            });
            TransferStatus = $"Minerador selecionado: {selectedMiner}.";
            AppendImportantFlowLog($"Transferência {transferId}: minerador selecionado {selectedMiner}.");
            _pendingMinerSelections.Remove(transferId);
        });

        _socketClient.On("miner_selector_ack", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            var transferId = payload.TryGetProperty("transfer_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() ?? string.Empty : string.Empty;
            var declined = payload.TryGetProperty("declined", out var declinedProp) && declinedProp.GetBoolean();
            var miner = payload.TryGetProperty("miner", out var minerProp) ? minerProp.GetString() ?? string.Empty : string.Empty;

            if (!success)
            {
                if (!string.IsNullOrWhiteSpace(error))
                {
                    TransferStatus = $"Seleção de minerador falhou: {error}";
                    AppendImportantFlowLog(string.IsNullOrWhiteSpace(transferId)
                        ? $"Seleção de minerador falhou: {error}"
                        : $"Transferência {transferId}: seleção de minerador falhou ({error}).");
                }
                return;
            }

            if (declined)
            {
                AppendImportantFlowLog(string.IsNullOrWhiteSpace(transferId)
                    ? "Seleção de minerador recusada."
                    : $"Transferência {transferId}: seleção de minerador recusada.");
                return;
            }

            if (!string.IsNullOrWhiteSpace(miner))
            {
                TransferStatus = $"Minerador selecionado: {miner}.";
            }
        });

        _socketClient.On("transfer_payload", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("error", out var errProp))
            {
                TransferStatus = $"Falha ao obter transferência: {errProp.GetString()}";
                if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
                return;
            }

            var contentB64 = payload.TryGetProperty("content_b64", out var contentProp) ? contentProp.GetString() : null;
            if (string.IsNullOrWhiteSpace(contentB64))
            {
                TransferStatus = "Arquivo de transferência não encontrado.";
                if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
                return;
            }

            try
            {
                var content = Convert.FromBase64String(contentB64);
                var title = payload.TryGetProperty("title", out var titleProp) ? titleProp.GetString() ?? string.Empty : string.Empty;
                var description = payload.TryGetProperty("description", out var descProp) ? descProp.GetString() ?? string.Empty : string.Empty;
                var mime = payload.TryGetProperty("mime_type", out var mimeProp) ? mimeProp.GetString() ?? "application/octet-stream" : "application/octet-stream";
                if (string.Equals(_pendingTransferAction, "accept", StringComparison.OrdinalIgnoreCase))
                {
                    _pendingTransferAction = null;
                    if (string.Equals(_pendingTransferType, "content", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(_pendingTransferType, "file", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(_pendingTransferType, "api_app", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(_pendingTransferType, "domain", StringComparison.OrdinalIgnoreCase))
                    {
                        _ = UploadTransferContentAsync(title, description, mime, content);
                        return;
                    }
                }
                _ = UploadContentBytesAsync(title, description, mime, content);
            }
            catch
            {
                TransferStatus = "Arquivo de transferência inválido.";
                if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
            }
        });

        _socketClient.On("accept_hps_transfer_ack", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
            {
                TransferStatus = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() ?? string.Empty : "Transação em análise.";
                return;
            }

            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
                TransferStatus = $"Falha ao aceitar transferência: {error}";
                ReleasePendingHpsPayment("contract_transfer");
                if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
                return;
            }

            TransferStatus = "Transferência HPS aceita.";
            ClearPendingHpsPayment("contract_transfer");
            QueueAutomaticPendingTransfersRefresh(includeMiner: false);
            if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
            {
                MarkImportantFlowDone();
            }
        });

        _socketClient.On("reject_transfer_ack", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
            {
                TransferStatus = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() ?? string.Empty : "Transação em análise.";
                return;
            }

            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
                TransferStatus = $"Falha ao rejeitar transferência: {error}";
                ReleasePendingHpsPayment("contract_transfer");
                if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
                return;
            }

            TransferStatus = "Transferência rejeitada.";
            ClearPendingHpsPayment("contract_transfer");
            QueueAutomaticPendingTransfersRefresh(includeMiner: false);
            if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
            {
                MarkImportantFlowDone();
            }
        });

        _socketClient.On("renounce_transfer_ack", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
            {
                TransferStatus = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() ?? string.Empty : "Transação em análise.";
                return;
            }

            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
                TransferStatus = $"Falha ao renunciar transferência: {error}";
                ReleasePendingHpsPayment("contract_transfer");
                if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
                return;
            }

            TransferStatus = "Transferência renunciada.";
            ClearPendingHpsPayment("contract_transfer");
            QueueAutomaticPendingTransfersRefresh(includeMiner: false);
            if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
            {
                MarkImportantFlowDone();
            }
        });

        _socketClient.On("report_result", response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
            {
                var message = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() ?? string.Empty : "Transação em análise.";
                TransferStatus = message;
                return;
            }
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
                TransferStatus = $"Falha ao reportar conteúdo: {error}";
                ReleasePendingHpsPayment("report");
                return;
            }
            TransferStatus = "Conteúdo reportado com sucesso.";
            ClearPendingHpsPayment("report");
        });

        _socketClient.OnAsync("request_content_from_client", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var contentHash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() : null;
            if (string.IsNullOrWhiteSpace(contentHash))
            {
                return;
            }
            await SendContentToServerAsync(contentHash);
        });

        _socketClient.OnAsync("request_ddns_from_client", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var domain = payload.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() : null;
            if (string.IsNullOrWhiteSpace(domain))
            {
                return;
            }
            await SendDdnsToServerAsync(domain);
        });

        _socketClient.OnAsync("request_contract_from_client", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            var contractId = payload.TryGetProperty("contract_id", out var idProp) ? idProp.GetString() : null;
            if (string.IsNullOrWhiteSpace(contractId))
            {
                return;
            }
            await SendContractToServerAsync(contractId);
        });

        _socketClient.On("ddns_from_client", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var domain = payload.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() : null;
            var ddnsContentB64 = payload.TryGetProperty("ddns_content", out var contentProp) ? contentProp.GetString() : null;
            var contentHash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() : null;
            var username = payload.TryGetProperty("username", out var userProp) ? userProp.GetString() : null;
            var signature = payload.TryGetProperty("signature", out var sigProp) ? sigProp.GetString() ?? string.Empty : string.Empty;
            var publicKey = payload.TryGetProperty("public_key", out var keyProp) ? keyProp.GetString() ?? string.Empty : string.Empty;
            var verified = payload.TryGetProperty("verified", out var verProp) && verProp.GetBoolean();

            if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(ddnsContentB64) ||
                string.IsNullOrWhiteSpace(contentHash) || string.IsNullOrWhiteSpace(username))
            {
                return;
            }

            try
            {
                var ddnsBytes = Convert.FromBase64String(ddnsContentB64);
                var ddnsHash = _contentService.ComputeSha256HexBytes(ddnsBytes);
                _contentService.SaveDdnsToStorage(domain, ddnsBytes, ddnsHash, contentHash, username, signature, publicKey);
                _database.SaveDnsRecord(domain, contentHash, username, verified);
                LoadDnsRecords();
                ScheduleClientPropagationSync();
            }
            catch
            {
                // Ignore malformed data.
            }
        });

        _socketClient.On("contract_from_client", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var contractId = payload.TryGetProperty("contract_id", out var idProp) ? idProp.GetString() : null;
            var contractContentB64 = payload.TryGetProperty("contract_content", out var contentProp) ? contentProp.GetString() : null;
            if (string.IsNullOrWhiteSpace(contractId) || string.IsNullOrWhiteSpace(contractContentB64))
            {
                return;
            }

            var contractInfo = new ContractInfo
            {
                ContractId = contractId,
                ActionType = payload.TryGetProperty("action_type", out var actionProp) ? actionProp.GetString() ?? string.Empty : string.Empty,
                ContentHash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty,
                Domain = payload.TryGetProperty("domain", out var domainProp) ? domainProp.GetString() ?? string.Empty : string.Empty,
                Username = payload.TryGetProperty("username", out var userProp) ? userProp.GetString() ?? string.Empty : string.Empty,
                Signature = payload.TryGetProperty("signature", out var sigProp) ? sigProp.GetString() ?? string.Empty : string.Empty,
                Verified = payload.TryGetProperty("verified", out var verProp) && verProp.GetBoolean() ? "Sim" : "Não",
                Timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            };

            try
            {
                contractInfo.ContractContent = Encoding.UTF8.GetString(Convert.FromBase64String(contractContentB64));
            }
            catch
            {
                contractInfo.ContractContent = contractContentB64;
            }

            _database.SaveContractRecord(contractInfo);
            ScheduleClientPropagationSync();
        });

        _socketClient.On("certify_missing_contract_ack", response =>
        {
            var payload = response.GetValue<JsonElement>();
            var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
            if (!success)
            {
                var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() ?? "Erro desconhecido" : "Erro desconhecido";
                CriticalBrowserErrorMessage = $"Falha ao certificar o contrato ausente: {error}";
                _pendingCriticalContractCertification = null;
                return;
            }

            CriticalBrowserErrorMessage = "Contrato ausente certificado. Recarregue o endereço para tentar novamente.";
            CanResolveCriticalBrowserError = false;
            (ResolveCriticalBrowserErrorCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
            _pendingCriticalContractCertification = null;
        });

        _socketClient.OnAsync("client_contracts_response", async response =>
        {
            var payload = response.GetValue<JsonElement>();
            if (!payload.TryGetProperty("missing_contracts", out var missingProp) || missingProp.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            foreach (var idElem in missingProp.EnumerateArray())
            {
                var contractId = idElem.GetString();
                if (string.IsNullOrWhiteSpace(contractId))
                {
                    continue;
                }
                await SendContractToServerAsync(contractId);
            }
        });
    }

    private void OnSocketConnected()
    {
        Interlocked.Exchange(ref _intentionalDisconnectInFlight, 0);
        _powChallengeTimeoutCts?.Cancel();
        _authenticationResultTcs?.TrySetCanceled();
        _authenticationResultTcs = null;
        Status = "Conectado (aguardando login)";
        _hasNetworkNodesSnapshot = false;
        HpsMiningStatus = IsLoggedIn ? "Pronto" : "Conectado";
        RaiseCommandCanExecuteChanged();
        _ = _socketClient.EmitAsync("request_server_auth_challenge", new { });
    }

    private bool ShouldAutoReconnect()
    {
        return AutoReconnect && Interlocked.CompareExchange(ref _intentionalDisconnectInFlight, 0, 0) == 0;
    }

    private void RunOnUi(Action action)
    {
        if (action is null)
        {
            return;
        }
        _dispatch(action);
    }

    private Task RunOnUiAsync(Action action)
    {
        if (action is null)
        {
            return Task.CompletedTask;
        }

        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _dispatch(() =>
        {
            try
            {
                action();
                tcs.TrySetResult(true);
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
            }
        });
        return tcs.Task;
    }

    private Task<T> RunOnUiAsync<T>(Func<Task<T>> action)
    {
        if (action is null)
        {
            return Task.FromResult(default(T)!);
        }

        var tcs = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        _dispatch(async () =>
        {
            try
            {
                var result = await action().ConfigureAwait(false);
                tcs.TrySetResult(result);
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
            }
        });
        return tcs.Task;
    }

    private void LogCli(string message)
    {
        if (_useUiDispatcher || string.IsNullOrWhiteSpace(message))
        {
            return;
        }
        Console.WriteLine(message);
    }

    private void OnSocketDisconnected()
    {
        var intentionalDisconnect = Interlocked.CompareExchange(ref _intentionalDisconnectInFlight, 0, 0) != 0;
        _powChallengeTimeoutCts?.Cancel();
        _authenticationResultTcs?.TrySetCanceled();
        _authenticationResultTcs = null;
        ResetExchangePendingRefreshState();
        Status = "Desconectado";
        User = "Não logado";
        IsLoggedIn = false;
        HpsMiningStatus = "Aguardando conexão";
        _isContinuousMiningInFlight = false;
        _pendingWalletRefreshCts?.Cancel();
        if (intentionalDisconnect)
        {
            LoginStatus = "Saida da rede concluida.";
        }
        RaiseCommandCanExecuteChanged();
        if (ShouldAutoReconnect())
        {
            _ = RecoverSocketAsync("socket_disconnected");
        }
    }

    private async Task BootstrapAfterLoginAsync()
    {
        try
        {
            await JoinNetworkAsync().ConfigureAwait(false);
            await _socketClient.EmitAsync("request_hps_wallet", new { }).ConfigureAwait(false);
            await _socketClient.EmitAsync("request_economy_report", new { }).ConfigureAwait(false);
            await _socketClient.EmitAsync("request_price_settings", new { }).ConfigureAwait(false);
			await _socketClient.EmitAsync("get_phps_market", new { }).ConfigureAwait(false);
            await _socketClient.EmitAsync("get_pending_transfers", new { }).ConfigureAwait(false);
            await RequestMinerPendingTransfersAsync().ConfigureAwait(false);
            await SyncKnownServersAsync().ConfigureAwait(false);
            await SyncClientFilesAsync().ConfigureAwait(false);
            await SyncClientDnsFilesAsync().ConfigureAwait(false);
            await SyncClientContractsAsync().ConfigureAwait(false);

            var inventoryItems = await Task.Run(() => _database.LoadInventoryItems()).ConfigureAwait(false);
            RunOnUi(() =>
            {
                _myInventoryItems.Clear();
                foreach (var (contentHash, title, description, mime, size, username, isPublic) in inventoryItems)
                {
                    var item = new InventoryItem
                    {
                        ContentHash = contentHash,
                        Title = title,
                        Description = description,
                        MimeType = mime,
                        Size = size,
                        Owner = username,
                        Source = "local",
                        IsPublic = isPublic
                    };
                    item.PropertyChanged += OnInventoryItemPropertyChanged;
                    _myInventoryItems.Add(item);
                }
            });

            if (IsContinuousMiningEnabled)
            {
                await StartContinuousMiningAsync().ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            RunOnUi(() => LoginStatus = $"Carga pós-login falhou: {ex.Message}");
        }
    }

    private async Task RecoverSocketAsync(string reason)
    {
        if (!ShouldAutoReconnect())
        {
            return;
        }
        if (Interlocked.CompareExchange(ref _reconnectInFlight, 1, 0) != 0)
        {
            return;
        }

        try
        {
            await Task.Delay(1000).ConfigureAwait(false);
            if (_socketClient.IsConnected)
            {
                return;
            }

            RunOnUi(() =>
            {
                Status = "Reconectando...";
                LoginStatus = $"Reconectando automaticamente ({reason})...";
                HpsMiningStatus = "Reconectando";
            });

            await RunOnUiAsync(async () =>
            {
                await EnterNetworkAsync(skipPreflight: true);
                return true;
            }).ConfigureAwait(false);
            if (_socketClient.IsConnected)
            {
                LogAutoSign($"reconnected reason={reason}; refreshing miner pending transfers");
                await _socketClient.EmitAsync("get_miner_pending_transfers", new { }).ConfigureAwait(false);
                _ = Task.Run(TryRunDeferredAutoSignAsync);
            }
            else
            {
                RunOnUi(() =>
                {
                    LoginStatus = $"Falha na reconexao automatica: {reason}";
                    ShowCriticalBrowserError(
                        "HPS-RECONNECT-FAILED",
                        "Reconexão automática falhou",
                        $"A sessão caiu e o navegador não conseguiu restabelecer a conexão automaticamente ({reason}).");
                });
            }
        }
        catch (Exception ex)
        {
            RunOnUi(() =>
            {
                LoginStatus = $"Falha na reconexao automatica: {ex.Message}";
                ShowCriticalBrowserError(
                    "HPS-RECONNECT-FAILED",
                    "Reconexão automática falhou",
                    $"A sessão caiu e a tentativa automática de reconexão falhou: {ex.Message}");
            });
            LogAutoSign($"reconnect failed reason={reason} error={ex.Message}");
        }
        finally
        {
            Interlocked.Exchange(ref _reconnectInFlight, 0);
        }
    }

    private async Task RequestPowChallengeAsync(string actionType)
    {
        if (!await PreparePowSlotAsync(actionType))
        {
            return;
        }
        _lastPowActionType = actionType;
        if (string.IsNullOrWhiteSpace(_importantFlowKind))
        {
            var label = _hpsPowSkipLabels.TryGetValue(actionType, out var flowLabel) ? flowLabel : actionType;
            await RunOnUiAsync(() => StartImportantFlow("PoW", $"Solicitando PoW para {label}...", $"Ação: {actionType}", "pow")).ConfigureAwait(false);
        }
        if (!_socketClient.IsConnected)
        {
            await RunOnUiAsync(() =>
            {
                LoginStatus = "Conexao perdida ao solicitar PoW. Tentando reconectar...";
                PowStatus = "Conexao perdida ao solicitar PoW.";
            }).ConfigureAwait(false);
            if (ShouldAutoReconnect())
            {
                _ = RecoverSocketAsync("pow_request_without_socket");
            }
            return;
        }

        _powChallengeTimeoutCts?.Cancel();
        _powChallengeTimeoutCts = new CancellationTokenSource();
        var timeoutToken = _powChallengeTimeoutCts.Token;
        await _socketClient.EmitAsync("request_pow_challenge", new
        {
            client_identifier = ClientId,
            action_type = actionType
        });
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(15), timeoutToken).ConfigureAwait(false);
                if (timeoutToken.IsCancellationRequested)
                {
                    return;
                }
                RunOnUi(() =>
                {
                    if (!timeoutToken.IsCancellationRequested)
                    {
                        LoginStatus = $"Timeout ao solicitar PoW para {actionType}.";
                        PowStatus = $"Timeout ao solicitar PoW para {actionType}.";
                        HpsMiningStatus = "PoW sem resposta";
                    }
                });
                if (ShouldAutoReconnect())
                {
                    await RecoverSocketAsync("pow_request_timeout").ConfigureAwait(false);
                }
            }
            catch (TaskCanceledException)
            {
            }
        }, timeoutToken);
    }

    private async Task SendAuthenticationAsync(ulong powNonce, double hashrateObserved)
    {
        if (_privateKey is null)
        {
            LoginStatus = "Chave privada não disponível";
            return;
        }

        if (string.IsNullOrWhiteSpace(_clientAuthChallenge))
        {
            LoginStatus = "Desafio do cliente ausente";
            return;
        }

        var clientSignature = CryptoUtils.SignPayload(_privateKey, _clientAuthChallenge);
        var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));
        var authTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _authenticationResultTcs?.TrySetCanceled();
        _authenticationResultTcs = authTcs;

        LoginStatus = "Enviando login...";
        LogCli("[cli] enviando authenticate");
        var emitted = await _socketClient.EmitCriticalAsync("authenticate", new
        {
            username = Username,
            public_key = publicKeyB64,
            node_type = _nodeType,
            client_identifier = ClientId,
            pow_nonce = powNonce.ToString(),
            hashrate_observed = hashrateObserved,
            client_challenge_signature = Convert.ToBase64String(clientSignature),
            client_challenge = _clientAuthChallenge
        });
        if (!emitted)
        {
            LoginStatus = "Falha ao enviar login: conexão perdida.";
            IsLoggedIn = false;
            _authenticationResultTcs?.TrySetResult(false);
            if (ShouldAutoReconnect())
            {
                _ = RecoverSocketAsync("authenticate_emit_failed");
            }
            return;
        }

        using var authTimeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        var completed = await Task.WhenAny(authTcs.Task, Task.Delay(Timeout.Infinite, authTimeoutCts.Token));
        if (completed != authTcs.Task)
        {
            if (ReferenceEquals(_authenticationResultTcs, authTcs))
            {
                _authenticationResultTcs = null;
            }
            LoginStatus = "Falha no login: timeout aguardando confirmação do servidor.";
            IsLoggedIn = false;
            if (ShouldAutoReconnect())
            {
                _ = RecoverSocketAsync("authenticate_timeout");
            }
            return;
        }

        await authTcs.Task;
        if (ReferenceEquals(_authenticationResultTcs, authTcs))
        {
            _authenticationResultTcs = null;
        }
    }

    private async Task SubmitPendingCriticalContractCertificationAsync(ulong powNonce, double hashrateObserved)
    {
        if (_pendingCriticalContractCertification is null || !_socketClient.IsConnected)
        {
            return;
        }

        var pending = _pendingCriticalContractCertification;
        CriticalBrowserErrorMessage = "Enviando certificação da pendência contratual...";
        await _socketClient.EmitAsync("certify_missing_contract", new
        {
            target_type = pending.TargetType,
            target_id = pending.TargetId,
            contract_content = pending.ContractContentB64,
            pow_nonce = powNonce.ToString(),
            hashrate_observed = hashrateObserved
        });
    }

    private async Task SubmitPendingDnsAsync(ulong powNonce, double hashrateObserved, object? hpsPayment = null)
    {
        if (_pendingDns is null)
        {
            DnsStatus = "Registro DNS: payload pendente não encontrado";
            return;
        }

        var powNonceValue = hpsPayment is null ? powNonce.ToString() : string.Empty;
        var hashrateValue = hpsPayment is null ? hashrateObserved : 0.0;
        await _socketClient.EmitAsync("register_dns", new
        {
            domain = _pendingDns.Domain,
            ddns_content = Convert.ToBase64String(_pendingDns.DdnsContent),
            signature = _pendingDns.SignatureB64,
            public_key = _pendingDns.PublicKeyB64,
            pow_nonce = powNonceValue,
            hashrate_observed = hashrateValue,
            hps_payment = hpsPayment
        });

        _pendingDns = null;
        DnsStatus = "Registro DNS enviado.";
    }

    private async Task SubmitPendingUploadAsync(ulong powNonce, double hashrateObserved, object? hpsPayment = null)
    {
        if (_pendingUpload is null)
        {
            await RunOnUiAsync(() => UploadStatus = "Upload: payload pendente não encontrado").ConfigureAwait(false);
            return;
        }

        var powNonceValue = hpsPayment is null ? powNonce.ToString() : string.Empty;
        var hashrateValue = hpsPayment is null ? hashrateObserved : 0.0;
        await _socketClient.EmitAsync("publish_content", new
        {
            content_hash = _pendingUpload.ContentHash,
            title = _pendingUpload.Title,
            description = _pendingUpload.Description,
            mime_type = _pendingUpload.MimeType,
            size = _pendingUpload.Size,
            signature = _pendingUpload.SignatureB64,
            public_key = _pendingUpload.PublicKeyB64,
            content_b64 = _pendingUpload.ContentB64,
            pow_nonce = powNonceValue,
            hashrate_observed = hashrateValue,
            hps_payment = hpsPayment
        });

        _pendingUpload = null;
        await RunOnUiAsync(() => UploadStatus = "Upload enviado.").ConfigureAwait(false);
    }

    private async Task SubmitPendingUsageContractAsync(ulong powNonce, double hashrateObserved, object? hpsPayment = null)
    {
        if (_pendingUsageContract is null)
        {
            LoginStatus = "Contrato de uso: payload pendente não encontrado";
            return;
        }

        var powNonceValue = hpsPayment is null ? powNonce.ToString() : string.Empty;
        var hashrateValue = hpsPayment is null ? hashrateObserved : 0.0;
        await _socketClient.EmitAsync("accept_usage_contract", new
        {
            contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(_pendingUsageContract.ContractText)),
            public_key = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem)),
            client_identifier = ClientId,
            username = Username.Trim(),
            pow_nonce = powNonceValue,
            hashrate_observed = hashrateValue,
            hps_payment = hpsPayment
        });

        _pendingUsageContract = null;
        LoginStatus = "Contrato de uso enviado.";
    }

    private async Task SubmitPendingHpsTransferAsync(ulong powNonce, double hashrateObserved, object? hpsPayment = null)
    {
        if (_pendingHpsTransfer is null)
        {
            HpsActionStatus = "Transferência HPS: payload pendente não encontrado.";
            return;
        }

        var powNonceValue = hpsPayment is null ? powNonce.ToString() : string.Empty;
        var hashrateValue = hpsPayment is null ? hashrateObserved : 0.0;
        await _socketClient.EmitAsync("transfer_hps", new
        {
            target_user = _pendingHpsTransfer.TargetUser,
            amount = _pendingHpsTransfer.Amount,
            voucher_ids = _pendingHpsTransfer.VoucherIds,
            contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(_pendingHpsTransfer.ContractText)),
            pow_nonce = powNonceValue,
            hashrate_observed = hashrateValue,
            hps_payment = hpsPayment
        });
    }

    private async Task SubmitHpsMintAsync(ulong powNonce, double hashrateObserved)
    {
        if (_privateKey is null)
        {
            HpsMintStatus = "Chave privada não disponível.";
            return;
        }

        if (!_socketClient.IsConnected || !IsLoggedIn)
        {
            HpsMintStatus = "Conecte-se à rede para minerar HPS.";
            return;
        }

        var reason = string.IsNullOrWhiteSpace(HpsMintReason) ? "mining" : HpsMintReason.Trim();
        var details = new Dictionary<string, string>
        {
            { "REASON", reason }
        };
        if (!string.IsNullOrWhiteSpace(_pendingHpsMintVoucherId))
        {
            details["VOUCHER_ID"] = _pendingHpsMintVoucherId!;
        }

        var contractTemplate = _contentService.BuildContractTemplate("hps_mint", details);
        var signedContract = _contentService.ApplyContractSignature(contractTemplate, _privateKey, User);

        await _socketClient.EmitAsync("mint_hps_voucher", new
        {
            pow_nonce = powNonce.ToString(),
            hashrate_observed = hashrateObserved,
            reason,
            contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract))
        });

        _pendingHpsMintVoucherId = null;
        HpsMintStatus = "Mineração enviada.";
    }

    private async Task ConfirmExchangeAsync()
    {
        if (string.IsNullOrWhiteSpace(_pendingExchangeQuoteId))
        {
            return;
        }

        StartImportantFlow("Câmbio", "Preparando câmbio...", $"Cotação: {_pendingExchangeQuoteId}", "transfer");
        UpdateImportantFlowStatus("Desbloqueando vouchers e preparando a confirmação do câmbio...");
        await _socketClient.EmitAsync("confirm_exchange", new
        {
            quote_id = _pendingExchangeQuoteId
        });

        ExchangeStatus = "Confirmando câmbio...";
        UpdateImportantFlowStatus("Confirmação enviada. Aguardando retorno do servidor.");
    }

    private async Task ShowExchangeConfirmPromptAsync(double rate, int converted, int fee, int receive)
    {
        if (_owner is null)
        {
            _exchangeConfirmPromptOpen = false;
            return;
        }
        try
        {
            var confirm = await _promptService.ConfirmAsync(
                _owner,
                "Cotação Recebida",
                $"Taxa de câmbio: {rate:0.0000}\nValor convertido: {converted} HPS\nTaxa cobrada: {fee} HPS\nValor líquido: {receive} HPS\n\nDeseja confirmar agora?",
                "Confirmar",
                "Depois");
            if (confirm && !string.IsNullOrWhiteSpace(_pendingExchangeQuoteId))
            {
                await ConfirmExchangeAsync();
            }
        }
        finally
        {
            _exchangeConfirmPromptOpen = false;
        }
    }

    private async Task SearchContractsAsync()
    {
        if (!_socketClient.IsConnected)
        {
            ContractDetailsText = "Conecte-se à rede primeiro.";
            return;
        }

        var searchType = string.IsNullOrWhiteSpace(ContractFilter) ? "all" : ContractFilter;
        var searchValue = ContractSearchValue?.Trim() ?? string.Empty;

        if (string.Equals(searchType, "api_app", StringComparison.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(searchValue))
        {
            ContractDetailsText = "Informe o nome do API APP para buscar.";
            return;
        }

        ContractCurrentPage = 1;
        _contractFetchedResults.Clear();
        _contractFilteredResults.Clear();
        Contracts.Clear();
        ContractTotalCount = 0;
        _contractServerTotalCount = 0;
        _contractLoadingPage = true;
        RaiseCommandCanExecuteChanged();
        ContractDetailsText = "Buscando contratos...";
        ResolveServerContractsSearch(searchType, searchValue, out var serverSearchType, out var serverSearchValue);
        _contractLastServerSearchType = serverSearchType;
        _contractLastServerSearchValue = serverSearchValue;
        var requestId = Interlocked.Increment(ref _contractSearchRequestVersion).ToString(CultureInfo.InvariantCulture);
        await _socketClient.EmitAsync("search_contracts", new
        {
            request_id = requestId,
            search_type = serverSearchType,
            search_value = serverSearchValue,
            limit = ContractChunkSize,
            offset = 0
        });
    }

    private async Task NextContractsPageAsync()
    {
        if (!_socketClient.IsConnected || _contractLoadingPage)
        {
            return;
        }

        var nextPage = ContractCurrentPage + 1;
        var requiredItems = nextPage * ContractChunkSize;
        if (_contractFilteredResults.Count >= requiredItems)
        {
            ContractCurrentPage = nextPage;
            RenderContractsCurrentPage();
            return;
        }

        if (_contractFetchedResults.Count >= _contractServerTotalCount)
        {
            return;
        }

        _contractLoadingPage = true;
        RaiseCommandCanExecuteChanged();
        ContractCurrentPage = nextPage;
        ContractDetailsText = $"Carregando página {nextPage} de contratos...";
        var requestId = Interlocked.Increment(ref _contractSearchRequestVersion).ToString(CultureInfo.InvariantCulture);
        await _socketClient.EmitAsync("search_contracts", new
        {
            request_id = requestId,
            search_type = _contractLastServerSearchType,
            search_value = _contractLastServerSearchValue,
            limit = nextPage * ContractChunkSize,
            offset = 0
        });
    }

    private void PreviousContractsPage()
    {
        if (ContractCurrentPage <= 1 || _contractLoadingPage)
        {
            return;
        }

        ContractCurrentPage -= 1;
        RenderContractsCurrentPage();
    }

    private bool CanGoNextContractsPage()
    {
        if (_contractLoadingPage)
        {
            return false;
        }

        var bufferedNextPage = _contractFilteredResults.Count > ContractCurrentPage * ContractChunkSize;
        if (bufferedNextPage)
        {
            return true;
        }

        return _contractFetchedResults.Count < _contractServerTotalCount;
    }

    private void ClearContracts()
    {
        ContractSearchValue = string.Empty;
        ContractFilter = "all";
        _contractFetchedResults.Clear();
        _contractFilteredResults.Clear();
        ContractCurrentPage = 1;
        ContractTotalCount = 0;
        _contractServerTotalCount = 0;
        _contractLoadingPage = false;
        Contracts.Clear();
        ContractDetailsText = string.Empty;
        RaiseCommandCanExecuteChanged();
    }

    private void ResolveServerContractsSearch(string searchType, string searchValue, out string serverSearchType, out string serverSearchValue)
    {
        if (string.Equals(searchType, "title", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(searchType, "api_app", StringComparison.OrdinalIgnoreCase))
        {
            serverSearchType = "all";
            serverSearchValue = string.Empty;
            return;
        }

        if (string.Equals(searchType, "all", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(searchValue))
        {
            serverSearchType = "all";
            serverSearchValue = string.Empty;
            return;
        }

        serverSearchType = string.IsNullOrWhiteSpace(searchType) ? "all" : searchType;
        serverSearchValue = searchValue;
    }

    private void ApplyContractSearchFilterAndSort()
    {
        var filterType = string.IsNullOrWhiteSpace(ContractFilter) ? "all" : ContractFilter.Trim().ToLowerInvariant();
        var query = NormalizeSearchText(ContractSearchValue);
        _contractFilteredResults.Clear();

        if (string.IsNullOrWhiteSpace(query))
        {
            foreach (var contract in _contractFetchedResults.OrderByDescending(c => c.Timestamp))
            {
                _contractFilteredResults.Add(contract);
            }
        }
        else
        {
            var ranked = _contractFetchedResults
                .Select(contract => (contract, score: GetContractMatchScore(contract, filterType, query)))
                .Where(item => item.score > 0)
                .OrderByDescending(item => item.score)
                .ThenByDescending(item => item.contract.Timestamp);

            foreach (var (contract, _) in ranked)
            {
                _contractFilteredResults.Add(contract);
            }
        }

        ContractTotalCount = _contractFilteredResults.Count;
        if (ContractCurrentPage > ContractTotalPages)
        {
            ContractCurrentPage = ContractTotalPages;
        }
    }

    private void RenderContractsCurrentPage()
    {
        var selectedId = SelectedContract?.ContractId;
        Contracts.Clear();

        if (_contractFilteredResults.Count == 0)
        {
            SelectedContract = null;
            ContractDetailsText = "Nenhum contrato encontrado para o filtro atual.";
            RaiseCommandCanExecuteChanged();
            return;
        }

        var start = Math.Max(0, (ContractCurrentPage - 1) * ContractChunkSize);
        if (start >= _contractFilteredResults.Count)
        {
            ContractCurrentPage = ContractTotalPages;
            start = Math.Max(0, (ContractCurrentPage - 1) * ContractChunkSize);
        }

        foreach (var contract in _contractFilteredResults.Skip(start).Take(ContractChunkSize))
        {
            Contracts.Add(contract);
        }

        UpdateContractPendingFlags();
        UpdateContractViolationFlags(string.Empty);

        if (!string.IsNullOrWhiteSpace(selectedId))
        {
            SelectedContract = Contracts.FirstOrDefault(c => string.Equals(c.ContractId, selectedId, StringComparison.OrdinalIgnoreCase));
        }

        if (SelectedContract is null)
        {
            ContractDetailsText = $"Exibindo {Contracts.Count} contrato(s) da página {ContractCurrentPage}/{ContractTotalPages}. " +
                                  $"Filtrados: {ContractTotalCount}. Carregados: {_contractFetchedResults.Count}/{_contractServerTotalCount}.";
        }
        RaiseCommandCanExecuteChanged();
    }

    private double GetContractMatchScore(ContractInfo contract, string filterType, string query)
    {
        if (contract is null || string.IsNullOrWhiteSpace(query))
        {
            return 1.0;
        }

        var title = NormalizeSearchText(contract.ContractTitle);
        var contentHash = NormalizeSearchText(contract.ContentHash);
        var domain = NormalizeSearchText(contract.Domain);
        var user = NormalizeSearchText(contract.Username);
        var actionType = NormalizeSearchText(contract.ActionType);
        var contractId = NormalizeSearchText(contract.ContractId);
        var allFields = $"{title} {contractId} {contentHash} {domain} {user} {actionType}";

        return filterType switch
        {
            "hash" => ScoreAgainstField(query, contentHash),
            "domain" => ScoreAgainstField(query, domain),
            "user" => ScoreAgainstField(query, user),
            "type" => ScoreAgainstField(query, actionType),
            "title" => ScoreAgainstField(query, title),
            "api_app" => ScoreAgainstField(query, title),
            _ => new[]
            {
                ScoreAgainstField(query, title),
                ScoreAgainstField(query, contractId),
                ScoreAgainstField(query, contentHash),
                ScoreAgainstField(query, domain),
                ScoreAgainstField(query, user),
                ScoreAgainstField(query, actionType),
                ScoreAgainstField(query, allFields)
            }.Max()
        };
    }

    private static double ScoreAgainstField(string query, string field)
    {
        if (string.IsNullOrWhiteSpace(query) || string.IsNullOrWhiteSpace(field))
        {
            return 0;
        }

        if (string.Equals(query, field, StringComparison.Ordinal))
        {
            return 1.0;
        }

        if (field.Contains(query, StringComparison.Ordinal))
        {
            return 0.92;
        }

        var tokens = query.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (tokens.Length > 0)
        {
            var hits = tokens.Count(token => field.Contains(token, StringComparison.Ordinal));
            if (hits == tokens.Length)
            {
                return Math.Max(0.82, hits / (double)tokens.Length);
            }
        }

        var similarity = LevenshteinSimilarity(query, field);
        return similarity >= 0.60 ? similarity * 0.75 : 0;
    }

    private static string NormalizeSearchText(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var text = RemoveDiacritics(value).ToLowerInvariant();
        var compact = Regex.Replace(text, "\\s+", " ").Trim();
        return compact;
    }

    private static string RemoveDiacritics(string value)
    {
        var normalized = value.Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder(normalized.Length);
        foreach (var ch in normalized)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(ch) != UnicodeCategory.NonSpacingMark)
            {
                sb.Append(ch);
            }
        }
        return sb.ToString().Normalize(NormalizationForm.FormC);
    }

    private static double LevenshteinSimilarity(string source, string target)
    {
        if (string.IsNullOrWhiteSpace(source) || string.IsNullOrWhiteSpace(target))
        {
            return 0;
        }

        var left = source;
        var right = target.Length > 96 ? target[..96] : target;
        var n = left.Length;
        var m = right.Length;
        var d = new int[n + 1, m + 1];

        for (var i = 0; i <= n; i++)
        {
            d[i, 0] = i;
        }
        for (var j = 0; j <= m; j++)
        {
            d[0, j] = j;
        }

        for (var i = 1; i <= n; i++)
        {
            for (var j = 1; j <= m; j++)
            {
                var cost = left[i - 1] == right[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(
                    Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1),
                    d[i - 1, j - 1] + cost);
            }
        }

        var distance = d[n, m];
        var maxLen = Math.Max(n, m);
        return maxLen == 0 ? 1 : 1 - (distance / (double)maxLen);
    }

    private async Task AnalyzeVouchersAsync()
    {
        if (!_socketClient.IsConnected)
        {
            VoucherAuditSummary = "Conecte-se à rede primeiro.";
            return;
        }

        var ids = ParseIdList(VoucherAuditInput);
        if (ids.Count == 0)
        {
            VoucherAuditSummary = "Informe os IDs dos vouchers.";
            return;
        }

        VoucherAuditSummary = "Solicitando análise de vouchers...";
        VoucherAuditDetails = string.Empty;
        _pendingVoucherAuditRequestId = Guid.NewGuid().ToString("N");
        await _socketClient.EmitAsync("request_voucher_audit", new
        {
            voucher_ids = ids,
            request_id = _pendingVoucherAuditRequestId
        });
    }

    private void ClearVoucherAudit()
    {
        VoucherAuditInput = string.Empty;
        VoucherAuditSummary = string.Empty;
        VoucherAuditDetails = string.Empty;
        _pendingVoucherAuditRequestId = null;
    }

    private async Task OpenVoucherAuditContractAsync()
    {
        var contractId = VoucherAuditInput?.Trim();
        if (string.IsNullOrWhiteSpace(contractId))
        {
            VoucherAuditSummary = "Informe o ID do contrato no campo de entrada.";
            return;
        }
        await OpenContractByIdAsync(contractId);
    }

    private async Task AnalyzeSpendAsync()
    {
        if (!_socketClient.IsConnected)
        {
            SpendAuditSummary = "Conecte-se à rede primeiro.";
            return;
        }

        var ids = ParseIdList(SpendAuditInput);
        if (ids.Count == 0)
        {
            SpendAuditSummary = "Informe IDs de vouchers para análise.";
            return;
        }

        SpendAuditSummary = "Solicitando análise de gastos...";
        SpendAuditDetails = string.Empty;
        _pendingSpendAuditRequestId = Guid.NewGuid().ToString("N");
        await _socketClient.EmitAsync("request_exchange_trace", new
        {
            voucher_ids = ids,
            request_id = _pendingSpendAuditRequestId
        });
    }

    private void ClearSpendAudit()
    {
        SpendAuditInput = string.Empty;
        SpendAuditSummary = string.Empty;
        SpendAuditDetails = string.Empty;
        _pendingSpendAuditRequestId = null;
    }

    private async Task OpenSpendContractAsync()
    {
        var contractId = SpendAuditInput?.Trim();
        if (string.IsNullOrWhiteSpace(contractId))
        {
            SpendAuditSummary = "Informe o ID do contrato no campo de entrada.";
            return;
        }
        await OpenContractByIdAsync(contractId);
    }

    private async Task OpenContractByIdAsync(string contractId)
    {
        if (_owner is null)
        {
            return;
        }
        var contractText = await _serverApiClient.FetchContractAsync(ServerAddress, UseSsl, contractId);
        if (string.IsNullOrWhiteSpace(contractText))
        {
            VoucherAuditSummary = "Contrato não encontrado.";
            SpendAuditSummary = "Contrato não encontrado.";
            return;
        }
        var window = new ContractWindow();
        window.SetContent($"Contrato {contractId}", contractText);
        await window.ShowDialog<ContractDialogResult>(_owner);
    }

    private async Task<List<VoucherAuditEntry>> FetchVoucherAuditAsync(List<string> voucherIds, string? transferId)
    {
        if (!_socketClient.IsConnected || voucherIds.Count == 0)
        {
            return new List<VoucherAuditEntry>();
        }

        var requestId = Guid.NewGuid().ToString("N");
        var tcs = new TaskCompletionSource<List<VoucherAuditEntry>>(TaskCreationOptions.RunContinuationsAsynchronously);
        _voucherAuditWaiters[requestId] = tcs;

        await _socketClient.EmitAsync("request_voucher_audit", new
        {
            request_id = requestId,
            voucher_ids = voucherIds,
            transfer_id = transferId ?? string.Empty
        });

        var delayTask = Task.Delay(TimeSpan.FromSeconds(6));
        var completed = await Task.WhenAny(tcs.Task, delayTask);
        _voucherAuditWaiters.Remove(requestId);
        if (completed == tcs.Task)
        {
            return await tcs.Task;
        }

        var direct = await _serverApiClient.FetchVoucherAuditAsync(ServerAddress, UseSsl, voucherIds);
        if (!direct.HasValue || direct.Value.ValueKind != JsonValueKind.Object)
        {
            return new List<VoucherAuditEntry>();
        }
        var directRoot = direct.Value;
        if (!directRoot.TryGetProperty("vouchers", out var vouchersProp) || vouchersProp.ValueKind != JsonValueKind.Array)
        {
            return new List<VoucherAuditEntry>();
        }
        var entries = new List<VoucherAuditEntry>();
        foreach (var item in vouchersProp.EnumerateArray())
        {
            entries.Add(new VoucherAuditEntry(item.GetRawText()));
        }
        return entries;
    }

    private async Task<List<ExchangeTraceEntry>> FetchExchangeTraceAsync(List<string> voucherIds)
    {
        if (!_socketClient.IsConnected || voucherIds.Count == 0)
        {
            return new List<ExchangeTraceEntry>();
        }

        var requestId = Guid.NewGuid().ToString("N");
        var tcs = new TaskCompletionSource<List<ExchangeTraceEntry>>(TaskCreationOptions.RunContinuationsAsynchronously);
        _exchangeTraceWaiters[requestId] = tcs;

        await _socketClient.EmitAsync("request_exchange_trace", new
        {
            request_id = requestId,
            voucher_ids = voucherIds
        });

        var delayTask = Task.Delay(TimeSpan.FromSeconds(6));
        var completed = await Task.WhenAny(tcs.Task, delayTask);
        _exchangeTraceWaiters.Remove(requestId);
        if (completed == tcs.Task)
        {
            return await tcs.Task;
        }

        return new List<ExchangeTraceEntry>();
    }

    private static List<string> ParseIdList(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return new List<string>();
        }
        var parts = raw.Split(new[] { ',', ';', '\n', '\r', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);
        return parts.Select(p => p.Trim())
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string FormatJson(JsonElement element)
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        return JsonSerializer.Serialize(element, options);
    }

    private sealed record VoucherAuditSummaryEntry(
        string VoucherId,
        string Owner,
        string Issuer,
        int Value,
        string Reason,
        string Status,
        bool Invalidated,
        bool PowOk,
        string PowReason,
        Dictionary<string, object> PowDetails
    )
    {
        public Dictionary<string, object> ToDictionary()
        {
            return new Dictionary<string, object>
            {
                ["voucher_id"] = VoucherId,
                ["owner"] = Owner,
                ["issuer"] = Issuer,
                ["value"] = Value,
                ["reason"] = Reason,
                ["status"] = Status,
                ["invalidated"] = Invalidated,
                ["pow_ok"] = PowOk,
                ["pow_reason"] = PowReason,
                ["pow_details"] = PowDetails
            };
        }
    }

    private sealed record InterServerEvidence(
        string Issuer,
        string IssuerPublicKey,
        string InterServerPayloadRaw,
        string IssuerServerInfoRaw,
        string IssuerValidateTokenRaw,
        string IssuerValidateSignature,
        List<string> IssuerVoucherIds,
        List<Dictionary<string, object>> IssuerVoucherAudit,
        string IssuerVoucherAuditRaw,
        string ReservedContractId,
        string ReservedContractBase64,
        string ReservedContractText,
        string OutContractId,
        string OutContractBase64,
        string OutContractText,
        string OwnerKeyContractId,
        string OwnerKeyContractBase64,
        string OwnerKeyContractText,
        string LineageCloseContractId,
        string LineageCloseContractBase64,
        string LineageCloseContractText,
        string ExchangeContractId,
        string ExchangeContractHash,
        string ExchangeContractBase64,
        string ExchangeContractText
    );

    private List<VoucherAuditSummaryEntry> BuildVoucherAuditSummary(List<VoucherAuditEntry> entries)
    {
        var summary = new List<VoucherAuditSummaryEntry>();
        foreach (var entry in entries)
        {
            using var doc = JsonDocument.Parse(entry.RawJson);
            var root = doc.RootElement;
            var voucherId = root.TryGetProperty("voucher_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            var status = root.TryGetProperty("status", out var statusProp) ? statusProp.GetString() ?? string.Empty : string.Empty;
            var invalidated = root.TryGetProperty("invalidated", out var invProp) && invProp.ValueKind == JsonValueKind.True;

            var payload = ExtractPayloadElement(root);
            var owner = GetJsonString(payload, "owner");
            var issuer = GetJsonString(payload, "issuer");
            var value = GetJsonInt(payload, "value");
            var reason = GetJsonString(payload, "reason");
            var (powOk, powReason, powDetails) = VerifyVoucherPowPayload(payload);

            summary.Add(new VoucherAuditSummaryEntry(
                voucherId,
                owner,
                issuer,
                value,
                reason,
                status,
                invalidated,
                powOk,
                powReason,
                powDetails
            ));
        }
        return summary;
    }

    private (List<Dictionary<string, object>> PowAudit, List<Dictionary<string, object>> TraceEntries, Dictionary<string, string> TraceFailures)
        AnalyzeVoucherPowTrace(List<VoucherAuditEntry> entries, InterServerEvidence? interServerEvidence)
    {
        var powAudit = new List<Dictionary<string, object>>();
        var traceEntries = new List<Dictionary<string, object>>();
        var traceFailures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            using var doc = JsonDocument.Parse(entry.RawJson);
            var root = doc.RootElement;
            var voucherId = root.TryGetProperty("voucher_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            var payload = ExtractPayloadElement(root);
            var (powOk, powReason, powDetails) = VerifyVoucherPowPayload(payload);

            powAudit.Add(new Dictionary<string, object>
            {
                ["voucher_id"] = voucherId,
                ["pow_ok"] = powOk,
                ["pow_reason"] = powReason,
                ["pow_details"] = powDetails
            });

            var sourceIds = ExtractTraceSourceIds(root);
            var conditions = payload.TryGetProperty("conditions", out var condProp) && condProp.ValueKind == JsonValueKind.Object
                ? condProp
                : default;
            if (conditions.ValueKind == JsonValueKind.Object)
            {
                var type = GetJsonString(conditions, "type");
                if (string.Equals(type, "exchange", StringComparison.OrdinalIgnoreCase))
                {
                    var issuerIds = ExtractStringList(conditions, "issuer_voucher_ids");
                    if (issuerIds.Count > 0)
                    {
                        sourceIds = issuerIds;
                    }
                }
            }
            sourceIds = sourceIds.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

            var traceOk = powOk && GetJsonString(GetJsonObject(payload, "pow"), "action_type") == "hps_mint";
            if (!traceOk && sourceIds.Count == 0)
            {
                traceFailures[voucherId] = "trace_missing";
            }

            traceEntries.Add(new Dictionary<string, object>
            {
                ["voucher_id"] = voucherId,
                ["trace_ok"] = traceOk,
                ["source_vouchers"] = sourceIds
            });
        }

        return (powAudit, traceEntries, traceFailures);
    }

    private async Task<InterServerEvidence?> FetchExchangeInterServerEvidenceAsync(MonetaryTransferInfo transfer)
    {
        InterServerEvidence? FailInterServerEvidence(string reason)
        {
            var message = $"Transferência {transfer.TransferId}: evidência inter-servidor inválida ({reason}).";
            AppendImportantFlowLog(message);
            Console.WriteLine($"[exchange] {message}");
            return null;
        }

        if (!string.Equals(transfer.TransferType, "exchange_in", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        if (string.IsNullOrWhiteSpace(transfer.InterServerRaw))
        {
            return FailInterServerEvidence("payload ausente");
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(transfer.InterServerRaw);
        }
        catch (Exception ex)
        {
            return FailInterServerEvidence($"json inválido: {ex.Message}");
        }
        using (doc)
        {
        var root = doc.RootElement;
        var interServerPayloadRaw = root.GetRawText();
        var issuer = GetJsonString(root, "issuer_address");
        if (string.IsNullOrWhiteSpace(issuer))
        {
            issuer = GetJsonString(root, "issuer");
        }
        if (string.IsNullOrWhiteSpace(issuer))
        {
            issuer = transfer.Sender;
        }
        var issuerPublicKey = GetJsonString(root, "issuer_public_key");
        var reservedId = GetJsonString(root, "issuer_reserved_contract_id");
        var outId = GetJsonString(root, "issuer_out_contract_id");
        var ownerKeyId = GetJsonString(root, "issuer_owner_key_contract_id");
        var lineageCloseContractId = GetJsonString(root, "issuer_lineage_close_contract_id");
        var exchangeContractId = GetJsonString(root, "exchange_contract_id");
        var exchangeContractHash = GetJsonString(root, "exchange_contract_hash");
        var exchangeContractContentB64 = GetJsonString(root, "exchange_contract_content");
        var validateTokenRaw = root.TryGetProperty("exchange_token", out var validateTokenProp) ? validateTokenProp.GetRawText() : string.Empty;
        var validateSignature = GetJsonString(root, "exchange_signature");
        var reservedContractB64 = GetJsonString(root, "issuer_reserved_contract");
        var outContractB64 = GetJsonString(root, "issuer_out_contract");
        var ownerKeyContractB64 = GetJsonString(root, "issuer_owner_key_contract");
        var lineageCloseContractB64 = GetJsonString(root, "issuer_lineage_close_contract");
        var issuerVoucherIds = ExtractStringList(root, "issuer_voucher_ids");
        var issuerServerInfoRaw = string.Empty;

        if (string.IsNullOrWhiteSpace(issuer) ||
            string.IsNullOrWhiteSpace(exchangeContractId))
        {
            return FailInterServerEvidence($"campos obrigatórios ausentes: issuer='{issuer}', exchange_contract_id='{exchangeContractId}'");
        }

        static string DecodeContractText(string contractB64)
        {
            if (string.IsNullOrWhiteSpace(contractB64))
            {
                return string.Empty;
            }

            try
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(contractB64));
            }
            catch
            {
                return string.Empty;
            }
        }

        static string EnsureContractBase64(string contractB64, string contractText)
        {
            if (!string.IsNullOrWhiteSpace(contractB64))
            {
                return contractB64;
            }
            if (string.IsNullOrWhiteSpace(contractText))
            {
                return string.Empty;
            }
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(contractText));
        }

        async Task<string> FetchContractWithFallbackAsync(string primaryServer, string contractId)
        {
            if (string.IsNullOrWhiteSpace(contractId))
            {
                return string.Empty;
            }
            var text = await _serverApiClient.FetchContractAsync(primaryServer, UseSsl, contractId) ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(text))
            {
                return text;
            }
            return await _serverApiClient.FetchContractAsync(ServerAddress, UseSsl, contractId) ?? string.Empty;
        }

        var reservedText = DecodeContractText(reservedContractB64);
        if (string.IsNullOrWhiteSpace(reservedText))
        {
            reservedText = await FetchContractWithFallbackAsync(issuer, reservedId);
        }
        var outText = DecodeContractText(outContractB64);
        if (string.IsNullOrWhiteSpace(outText))
        {
            outText = await FetchContractWithFallbackAsync(issuer, outId);
        }
        var ownerKeyText = DecodeContractText(ownerKeyContractB64);
        if (string.IsNullOrWhiteSpace(ownerKeyText))
        {
            ownerKeyText = await FetchContractWithFallbackAsync(issuer, ownerKeyId);
        }
        var lineageCloseText = DecodeContractText(lineageCloseContractB64);
        if (string.IsNullOrWhiteSpace(lineageCloseText) && !string.IsNullOrWhiteSpace(lineageCloseContractId))
        {
            lineageCloseText = await FetchContractWithFallbackAsync(issuer, lineageCloseContractId);
        }
        if (string.IsNullOrWhiteSpace(reservedId) || string.IsNullOrWhiteSpace(reservedText))
        {
            return FailInterServerEvidence($"contrato reservado indisponível: id='{reservedId}'");
        }
        if (string.IsNullOrWhiteSpace(outId) || string.IsNullOrWhiteSpace(outText))
        {
            return FailInterServerEvidence($"contrato de saída indisponível: id='{outId}'");
        }
        if (string.IsNullOrWhiteSpace(ownerKeyId) || string.IsNullOrWhiteSpace(ownerKeyText))
        {
            return FailInterServerEvidence($"contrato de chave do owner indisponível: id='{ownerKeyId}'");
        }
        if (!string.IsNullOrWhiteSpace(lineageCloseContractId) && string.IsNullOrWhiteSpace(lineageCloseText))
        {
            return FailInterServerEvidence($"contrato de fechamento de linhagem indisponível: id='{lineageCloseContractId}'");
        }
        if (string.IsNullOrWhiteSpace(issuerPublicKey))
        {
            var serverInfo = await _serverApiClient.FetchServerInfoAsync(issuer, UseSsl);
            if (serverInfo.HasValue && serverInfo.Value.ValueKind == JsonValueKind.Object)
            {
                issuerServerInfoRaw = serverInfo.Value.GetRawText();
                issuerPublicKey = serverInfo.Value.TryGetProperty("public_key", out var keyProp) ? keyProp.GetString() ?? string.Empty : string.Empty;
            }
        }
        else
        {
            issuerServerInfoRaw = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["address"] = issuer,
                ["public_key"] = issuerPublicKey
            });
        }
        if (!string.IsNullOrWhiteSpace(lineageCloseText))
        {
            var lineageCloseSignature = ExtractContractDetail(lineageCloseText, "SIGNATURE");
            if (string.IsNullOrWhiteSpace(lineageCloseSignature) ||
                !TryVerifyContractSignature(issuerPublicKey, GetSignedContractText(lineageCloseText), lineageCloseSignature))
            {
                return FailInterServerEvidence("assinatura inválida no contrato de fechamento de linhagem");
            }
        }

        string exchangeContractText;
        if (!string.IsNullOrWhiteSpace(exchangeContractContentB64))
        {
            try
            {
                exchangeContractText = Encoding.UTF8.GetString(Convert.FromBase64String(exchangeContractContentB64));
            }
            catch
            {
                return FailInterServerEvidence("exchange_contract_content inválido");
            }
        }
        else
        {
            exchangeContractText = await FetchContractWithFallbackAsync(issuer, exchangeContractId);
            if (string.IsNullOrWhiteSpace(exchangeContractText))
            {
                return FailInterServerEvidence($"contrato local do câmbio indisponível: id='{exchangeContractId}'");
            }
        }

        if (string.IsNullOrWhiteSpace(exchangeContractHash))
        {
            exchangeContractHash = _contentService.ComputeSha256HexBytes(Encoding.UTF8.GetBytes(exchangeContractText));
        }
        var exchangeHash = _contentService.ComputeSha256HexBytes(Encoding.UTF8.GetBytes(exchangeContractText));
        if (!string.Equals(exchangeHash, exchangeContractHash, StringComparison.OrdinalIgnoreCase))
        {
            return FailInterServerEvidence($"hash do contrato do câmbio divergente: esperado='{exchangeContractHash}' atual='{exchangeHash}'");
        }
        var issuerVoucherAudit = new List<Dictionary<string, object>>();
        var issuerVoucherAuditRaw = string.Empty;
        if (issuerVoucherIds.Count > 0)
        {
            var audit = await _serverApiClient.FetchVoucherAuditAsync(issuer, UseSsl, issuerVoucherIds);
            if ((!audit.HasValue || audit.Value.ValueKind != JsonValueKind.Object) && !string.IsNullOrWhiteSpace(ServerAddress))
            {
                audit = await _serverApiClient.FetchVoucherAuditAsync(ServerAddress, UseSsl, issuerVoucherIds);
            }
            if (audit.HasValue && audit.Value.ValueKind == JsonValueKind.Object &&
                audit.Value.TryGetProperty("vouchers", out var vouchersProp) &&
                vouchersProp.ValueKind == JsonValueKind.Array)
            {
                issuerVoucherAuditRaw = audit.Value.GetRawText();
                foreach (var item in vouchersProp.EnumerateArray())
                {
                    issuerVoucherAudit.Add(JsonSerializer.Deserialize<Dictionary<string, object>>(item.GetRawText()) ?? new Dictionary<string, object>());
                }
            }
        }

        return new InterServerEvidence(
            issuer,
            issuerPublicKey,
            interServerPayloadRaw,
            issuerServerInfoRaw,
            validateTokenRaw,
            validateSignature,
            issuerVoucherIds,
            issuerVoucherAudit,
            issuerVoucherAuditRaw,
            reservedId,
            EnsureContractBase64(reservedContractB64, reservedText),
            reservedText,
            outId,
            EnsureContractBase64(outContractB64, outText),
            outText,
            ownerKeyId,
            EnsureContractBase64(ownerKeyContractB64, ownerKeyText),
            ownerKeyText,
            lineageCloseContractId,
            EnsureContractBase64(lineageCloseContractB64, lineageCloseText),
            lineageCloseText,
            exchangeContractId,
            exchangeContractHash,
            EnsureContractBase64(exchangeContractContentB64, exchangeContractText),
            exchangeContractText
        );
        }
    }

    private static JsonElement ExtractPayloadElement(JsonElement root)
    {
        if (!root.TryGetProperty("payload", out var payloadProp))
        {
            return default;
        }
        if (payloadProp.ValueKind == JsonValueKind.String)
        {
            var json = payloadProp.GetString() ?? "{}";
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.Clone();
        }
        if (payloadProp.ValueKind == JsonValueKind.Object)
        {
            return payloadProp.Clone();
        }
        return default;
    }

    private static List<string> ExtractTraceSourceIds(JsonElement root)
    {
        var sources = new List<string>();
        if (!root.TryGetProperty("trace_contracts", out var traceProp) || traceProp.ValueKind != JsonValueKind.Array)
        {
            return sources;
        }
        foreach (var contractElem in traceProp.EnumerateArray())
        {
            if (contractElem.ValueKind != JsonValueKind.Object)
            {
                continue;
            }
            var actionType = contractElem.TryGetProperty("action_type", out var actProp) ? actProp.GetString() ?? string.Empty : string.Empty;
            var contractB64 = contractElem.TryGetProperty("contract_content", out var contentProp) ? contentProp.GetString() ?? string.Empty : string.Empty;
            if (string.IsNullOrWhiteSpace(actionType) || string.IsNullOrWhiteSpace(contractB64))
            {
                continue;
            }
            string contractText;
            try
            {
                contractText = Encoding.UTF8.GetString(Convert.FromBase64String(contractB64));
            }
            catch
            {
                continue;
            }
            if (actionType is "hps_spend_refund" or "miner_fine_refund" or "hps_transfer_custody_refund")
            {
                var rawList = ExtractContractDetail(contractText, "VOUCHERS");
                if (!string.IsNullOrWhiteSpace(rawList))
                {
                    try
                    {
                        var ids = JsonSerializer.Deserialize<List<string>>(rawList) ?? new List<string>();
                        sources.AddRange(ids.Where(id => !string.IsNullOrWhiteSpace(id)));
                    }
                    catch
                    {
                        // ignore
                    }
                }
            }
            else if (actionType == "hps_transfer_refund")
            {
                var sourceId = ExtractContractDetail(contractText, "ORIGINAL_VOUCHER_ID");
                if (!string.IsNullOrWhiteSpace(sourceId))
                {
                    sources.Add(sourceId);
                }
            }
        }
        return sources;
    }

    private static (bool Ok, string Reason, Dictionary<string, object> Details) VerifyVoucherPowPayload(JsonElement payload)
    {
        var details = new Dictionary<string, object>
        {
            ["challenge"] = string.Empty,
            ["nonce"] = string.Empty,
            ["target_bits"] = 0,
            ["action_type"] = string.Empty,
            ["voucher_id_match"] = false,
            ["leading_zero_bits"] = 0
        };
        if (payload.ValueKind != JsonValueKind.Object)
        {
            return (false, "pow_missing", details);
        }
        var voucherId = GetJsonString(payload, "voucher_id");
        var pow = GetJsonObject(payload, "pow");
        var challenge = GetJsonString(pow, "challenge");
        var nonceText = GetJsonString(pow, "nonce");
        var targetBits = GetJsonInt(pow, "target_bits");
        var actionType = GetJsonString(pow, "action_type");
        var powVoucherId = GetJsonString(pow, "voucher_id");

        details["challenge"] = challenge;
        details["nonce"] = nonceText;
        details["target_bits"] = targetBits;
        details["action_type"] = actionType;
        details["voucher_id_match"] = string.IsNullOrWhiteSpace(powVoucherId) || string.Equals(powVoucherId, voucherId, StringComparison.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(challenge) || string.IsNullOrWhiteSpace(nonceText) || targetBits <= 0)
        {
            return (false, "pow_missing", details);
        }
        if (!string.IsNullOrWhiteSpace(powVoucherId) && !string.Equals(powVoucherId, voucherId, StringComparison.OrdinalIgnoreCase))
        {
            return (false, "pow_voucher_mismatch", details);
        }

        try
        {
            var challengeBytes = Convert.FromBase64String(challenge);
            if (!ulong.TryParse(nonceText, out var nonceValue))
            {
                return (false, "pow_invalid", details);
            }
            var data = new byte[challengeBytes.Length + 8];
            Buffer.BlockCopy(challengeBytes, 0, data, 0, challengeBytes.Length);
            BinaryPrimitives.WriteUInt64BigEndian(data.AsSpan(challengeBytes.Length), nonceValue);
            var hash = SHA256.HashData(data);
            var lzb = LeadingZeroBits(hash);
            details["leading_zero_bits"] = lzb;
            if (lzb < targetBits)
            {
                return (false, "pow_invalid", details);
            }
            if (string.Equals(actionType, "hps_mint", StringComparison.OrdinalIgnoreCase))
            {
                var challengeText = Encoding.ASCII.GetString(challengeBytes);
                if (!challengeText.StartsWith($"HPSMINT:{voucherId}:", StringComparison.Ordinal))
                {
                    return (false, "pow_challenge_mismatch", details);
                }
            }
        }
        catch
        {
            return (false, "pow_invalid", details);
        }

        return (true, string.Empty, details);
    }

    private static int LeadingZeroBits(byte[] hash)
    {
        var count = 0;
        foreach (var b in hash)
        {
            if (b == 0)
            {
                count += 8;
                continue;
            }
            for (var i = 7; i >= 0; i--)
            {
                if ((b & (1 << i)) != 0)
                {
                    return count;
                }
                count++;
            }
            break;
        }
        return count;
    }

    private static JsonElement GetJsonObject(JsonElement element, string property)
    {
        if (element.ValueKind == JsonValueKind.Object &&
            element.TryGetProperty(property, out var prop) &&
            prop.ValueKind == JsonValueKind.Object)
        {
            return prop;
        }
        return default;
    }

    private static string GetJsonString(JsonElement element, string property)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(property, out var prop))
        {
            return string.Empty;
        }
        if (prop.ValueKind == JsonValueKind.String)
        {
            return prop.GetString() ?? string.Empty;
        }
        if (prop.ValueKind == JsonValueKind.Number)
        {
            return prop.ToString();
        }
        return string.Empty;
    }

    private static int GetJsonInt(JsonElement element, string property)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(property, out var prop))
        {
            return 0;
        }
        if (prop.ValueKind == JsonValueKind.Number && prop.TryGetInt32(out var val))
        {
            return val;
        }
        if (prop.ValueKind == JsonValueKind.String && int.TryParse(prop.GetString(), out var parsed))
        {
            return parsed;
        }
        return 0;
    }

    private static List<string> ExtractStringList(JsonElement element, string property)
    {
        var result = new List<string>();
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(property, out var prop))
        {
            return result;
        }
        if (prop.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in prop.EnumerateArray())
            {
                var value = item.GetString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    result.Add(value);
                }
            }
        }
        else if (prop.ValueKind == JsonValueKind.String)
        {
            result.AddRange(ParseIdList(prop.GetString()));
        }
        return result;
    }

    private async Task SignTransferByIdAsync(string transferId)
    {
        if (string.IsNullOrWhiteSpace(transferId))
        {
            return;
        }
        var popupId = TransferFlowPopupId(transferId, "signature");
        if (Interlocked.CompareExchange(ref _signTransferInFlight, 1, 0) != 0)
        {
            _deferredAutoSignTransferId = transferId;
            return;
        }
        void FailSign(string message)
        {
            AppendPowLog(message);
            UpdateFlowPopupStatus(popupId, message);
            MarkFlowPopupDone(popupId);
        }
        try
        {
        if (_privateKey is null || !_socketClient.IsConnected || !IsLoggedIn)
        {
            LogAutoSign($"sign skipped transfer={transferId}: session unavailable connected={_socketClient.IsConnected} logged={IsLoggedIn} key={_privateKey is not null}");
            FailSign("Assinatura pendente: sessao indisponivel.");
            if (ShouldAutoReconnect())
            {
                _ = RecoverSocketAsync("sign_transfer_without_session");
            }
            return;
        }
        if (!_pendingMinerTransfers.TryGetValue(transferId, out var transfer))
        {
            LogAutoSign($"sign skipped transfer={transferId}: pending transfer not found");
            FailSign("Transferência pendente não encontrada.");
            return;
        }
        if (!CanSubmitMinerSignature(transferId))
        {
            LogAutoSign($"sign skipped transfer={transferId}: resend cooldown active");
            UpdateFlowPopupStatus(popupId, $"Assinatura de {transferId} já foi enviada. Aguardando confirmação do servidor.");
            return;
        }
        LogAutoSign($"sign preparing transfer={transferId} type={transfer.TransferType} sender={transfer.Sender} receiver={transfer.Receiver}");

        var start = DateTimeOffset.UtcNow;
        var voucherIds = transfer.LockedVoucherIds.Where(v => !string.IsNullOrWhiteSpace(v)).ToList();
        var auditResults = await FetchVoucherAuditAsync(voucherIds, transferId);
        var auditSummary = BuildVoucherAuditSummary(auditResults);

        var interServerEvidence = await FetchExchangeInterServerEvidenceAsync(transfer);
        if (string.Equals(transfer.TransferType, "exchange_in", StringComparison.OrdinalIgnoreCase) && interServerEvidence is null)
        {
            LogAutoSign($"sign aborted transfer={transferId}: missing inter-server evidence");
            FailSign($"Falha ao verificar dados inter-servidor para {transferId}.");
            return;
        }

        var (powAudit, traceEntries, traceFailures) = AnalyzeVoucherPowTrace(auditResults, interServerEvidence);
        var failures = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var voucher in auditSummary)
        {
            if (voucher.Invalidated || string.Equals(voucher.Status, "invalid", StringComparison.OrdinalIgnoreCase))
            {
                failures[voucher.VoucherId] = "voucher_invalidated";
            }
        }

        if (traceFailures.Count > 0)
        {
            foreach (var kvp in traceFailures)
            {
                failures[kvp.Key] = kvp.Value;
            }
        }

        if (voucherIds.Count > 0)
        {
            var auditedIds = new HashSet<string>(auditSummary.Select(a => a.VoucherId), StringComparer.OrdinalIgnoreCase);
            foreach (var vid in voucherIds)
            {
                if (!auditedIds.Contains(vid))
                {
                    failures[vid] = "audit_missing";
                }
            }
        }

        if (failures.Count > 0 && failures.All(f => f.Value is "audit_missing" or "trace_missing"))
        {
            failures.Clear();
        }

        if (failures.Count > 0)
        {
            LogAutoSign($"sign aborted transfer={transferId}: voucher failures={string.Join(",", failures.Select(kvp => kvp.Key + ":" + kvp.Value))}");
            lock (_pendingInvalidationTransfers)
            {
                if (_pendingInvalidationTransfers.Contains(transferId))
                {
                    AppendPowLog($"Invalidação já em andamento para {transferId}.");
                    return;
                }
                _pendingInvalidationTransfers.Add(transferId);
            }
            var invalidIds = failures.Keys.ToList();
            var evidence = new Dictionary<string, object>
            {
                ["failures"] = failures,
                ["audit"] = auditSummary.Select(a => a.ToDictionary()).ToList(),
                ["pow_audit"] = powAudit,
                ["trace"] = traceEntries
            };
            var details = new Dictionary<string, string>
            {
                { "TRANSFER_ID", transferId },
                { "REASON", "voucher_invalid" },
                { "VOUCHERS", JsonSerializer.Serialize(invalidIds) },
                { "EVIDENCE", JsonSerializer.Serialize(evidence) }
            };
            var invalidateTemplate = _contentService.BuildContractTemplate("voucher_invalidate", details);
            var signedText = _contentService.ApplyContractSignature(invalidateTemplate, _privateKey, User);
            await _socketClient.EmitAsync("invalidate_vouchers", new
            {
                contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedText))
            });
            AppendPowLog("Invalidação de vouchers enviada.");
            UpdateImportantFlowStatus("Invalidação de vouchers enviada.");
            MarkImportantFlowDone();
            return;
        }

        if (voucherIds.Count > 0 &&
            powAudit.Count == 0 &&
            !string.Equals(transfer.TransferType, "exchange_in", StringComparison.OrdinalIgnoreCase))
        {
            LogAutoSign($"sign aborted transfer={transferId}: missing local voucher audit");
            FailSign($"Auditoria indisponível para {transferId}. Assinatura cancelada.");
            return;
        }

        var reportDetails = new Dictionary<string, string>
        {
            { "TRANSFER_ID", transferId },
            { "TRANSFER_TYPE", transfer.TransferType },
            { "SENDER", transfer.Sender },
            { "RECEIVER", transfer.Receiver },
            { "AMOUNT", transfer.Amount.ToString() },
            { "FEE_AMOUNT", transfer.FeeAmount.ToString() },
            { "FEE_SOURCE", transfer.FeeSource },
            { "CONTRACT_ID", transfer.ContractId },
            { "LOCKED_VOUCHERS", JsonSerializer.Serialize(voucherIds) }
        };

        if (!string.Equals(transfer.TransferType, "exchange_in", StringComparison.OrdinalIgnoreCase))
        {
            reportDetails["VOUCHER_POW_AUDIT"] = JsonSerializer.Serialize(powAudit);
            reportDetails["VOUCHER_TRACE"] = JsonSerializer.Serialize(traceEntries);
        }

        if (interServerEvidence is not null)
        {
            reportDetails["INTER_SERVER_ISSUER"] = interServerEvidence.Issuer;
            reportDetails["INTER_SERVER_PAYLOAD"] = interServerEvidence.InterServerPayloadRaw;
            reportDetails["ISSUER_PUBLIC_KEY"] = interServerEvidence.IssuerPublicKey;
            reportDetails["ISSUER_SERVER_INFO"] = interServerEvidence.IssuerServerInfoRaw;
            reportDetails["ISSUER_VALIDATE_TOKEN"] = interServerEvidence.IssuerValidateTokenRaw;
            reportDetails["ISSUER_VALIDATE_SIGNATURE"] = interServerEvidence.IssuerValidateSignature;
            reportDetails["ISSUER_VOUCHER_IDS"] = JsonSerializer.Serialize(interServerEvidence.IssuerVoucherIds);
            reportDetails["ISSUER_VOUCHER_AUDIT"] = interServerEvidence.IssuerVoucherAuditRaw;
            reportDetails["ISSUER_RESERVED_CONTRACT_ID"] = interServerEvidence.ReservedContractId;
            reportDetails["ISSUER_RESERVED_CONTRACT"] = interServerEvidence.ReservedContractBase64;
            reportDetails["ISSUER_OUT_CONTRACT_ID"] = interServerEvidence.OutContractId;
            reportDetails["ISSUER_OUT_CONTRACT"] = interServerEvidence.OutContractBase64;
            reportDetails["ISSUER_OWNER_KEY_CONTRACT_ID"] = interServerEvidence.OwnerKeyContractId;
            reportDetails["ISSUER_OWNER_KEY_CONTRACT"] = interServerEvidence.OwnerKeyContractBase64;
            reportDetails["ISSUER_LINEAGE_CLOSE_CONTRACT_ID"] = interServerEvidence.LineageCloseContractId;
            reportDetails["ISSUER_LINEAGE_CLOSE_CONTRACT"] = interServerEvidence.LineageCloseContractBase64;
            reportDetails["CLIENT_EXCHANGE_CONTRACT_ID"] = interServerEvidence.ExchangeContractId;
            reportDetails["CLIENT_EXCHANGE_CONTRACT_HASH"] = interServerEvidence.ExchangeContractHash;
            reportDetails["CLIENT_EXCHANGE_CONTRACT"] = interServerEvidence.ExchangeContractBase64;
        }

        var reportTemplate = _contentService.BuildContractTemplate("miner_signature_report", reportDetails);
        var reportText = _contentService.ApplyContractSignature(reportTemplate, _privateKey, User);

        var contractDetails = new Dictionary<string, string>
        {
            { "TRANSFER_ID", transferId },
            { "TRANSFER_TYPE", transfer.TransferType },
            { "SENDER", transfer.Sender },
            { "RECEIVER", transfer.Receiver },
            { "AMOUNT", transfer.Amount.ToString() }
        };
        var signatureTemplate = _contentService.BuildContractTemplate("transfer_signature", contractDetails);
        var signedContract = _contentService.ApplyContractSignature(signatureTemplate, _privateKey, User);

        var elapsed = DateTimeOffset.UtcNow - start;
        if (elapsed.TotalSeconds < 4.0)
        {
            await Task.Delay(TimeSpan.FromSeconds(4.0 - elapsed.TotalSeconds));
        }

        var signedContractB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract));
        var reportTextB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(reportText));
        Console.WriteLine($"[sign_transfer] transfer={transferId} contract_b64={signedContractB64.Length} report_b64={reportTextB64.Length}");
        LogAutoSign($"sign emitting transfer={transferId} contract_b64={signedContractB64.Length} report_b64={reportTextB64.Length}");

        var emitted = await _socketClient.EmitCriticalAsync("sign_transfer", new
        {
            transfer_id = transferId,
            contract_content = signedContractB64,
            report_content = reportTextB64
        }).ConfigureAwait(false);
        if (!emitted)
        {
            LogAutoSign($"sign emit failed transfer={transferId}: socket emit returned false");
            FailSign($"Falha ao enviar assinatura de {transferId}: conexao perdida.");
            if (ShouldAutoReconnect())
            {
                _ = RecoverSocketAsync("sign_transfer_emit_failed");
            }
            return;
        }
        _submittedMinerTransferAt[transferId] = DateTimeOffset.UtcNow;
        LogAutoSign($"sign emitted transfer={transferId}");
        UpdateFlowPopupStatus(popupId, $"Assinatura enviada para {transferId}. Aguardando confirmação do servidor.");
        }
        finally
        {
            Interlocked.Exchange(ref _signTransferInFlight, 0);
            _ = Task.Run(TryRunDeferredAutoSignAsync);
        }
    }

    private string UpsertPendingMinerTransfer(JsonElement payload, bool triggerUiFlow)
    {
        var transferId = payload.TryGetProperty("transfer_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
        if (string.IsNullOrWhiteSpace(transferId))
        {
            return string.Empty;
        }

        var transferType = payload.TryGetProperty("transfer_type", out var typeProp) ? typeProp.GetString() ?? string.Empty : string.Empty;
        var sender = payload.TryGetProperty("sender", out var senderProp) ? senderProp.GetString() ?? string.Empty : string.Empty;
        var receiver = payload.TryGetProperty("receiver", out var receiverProp) ? receiverProp.GetString() ?? string.Empty : string.Empty;
        var amount = payload.TryGetProperty("amount", out var amountProp) ? amountProp.GetInt32() : 0;
        var feeAmount = payload.TryGetProperty("fee_amount", out var feeProp) ? feeProp.GetInt32() : 0;
        var feeSource = payload.TryGetProperty("fee_source", out var feeSourceProp) ? feeSourceProp.GetString() ?? string.Empty : string.Empty;
        var contractId = payload.TryGetProperty("contract_id", out var contractProp) ? contractProp.GetString() ?? string.Empty : string.Empty;
        var lockedVoucherIds = new List<string>();
        if (payload.TryGetProperty("locked_voucher_ids", out var lockedProp))
        {
            if (lockedProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in lockedProp.EnumerateArray())
                {
                    var id = item.GetString();
                    if (!string.IsNullOrWhiteSpace(id))
                    {
                        lockedVoucherIds.Add(id);
                    }
                }
            }
            else if (lockedProp.ValueKind == JsonValueKind.String)
            {
                lockedVoucherIds.AddRange(ParseIdList(lockedProp.GetString()));
            }
        }

        var interServerRaw = payload.TryGetProperty("inter_server", out var interProp)
            ? interProp.GetRawText()
            : string.Empty;

        _pendingMinerTransfers[transferId] = new MonetaryTransferInfo(
            transferId,
            transferType,
            sender,
            receiver,
            amount,
            feeAmount,
            feeSource,
            contractId,
            lockedVoucherIds,
            interServerRaw
        );
        UpdateAutomaticStateSyncLoop();
        RaiseCommandCanExecuteChanged();

        var pending = payload.TryGetProperty("pending_signatures", out var pendingProp) ? pendingProp.GetInt32() : _pendingMinerTransfers.Count;
        if (pending <= 0)
        {
            pending = _pendingMinerTransfers.Count;
        }
        MinerPendingSignatures = pending.ToString();
        LogAutoSign($"pending transfer upsert transfer={transferId} type={transferType} trigger={triggerUiFlow} pending={pending} deferred={_deferredAutoSignTransferId ?? "<none>"}");

        if (!triggerUiFlow)
        {
            return transferId;
        }

        if (AutoSignTransfers)
        {
            var details = $"Tipo: {transferType}\nRemetente: {sender}\nDestinatário: {receiver}";
            var popupId = TransferFlowPopupId(transferId, "signature");
            if (HasBlockingPowFlow() && !(IsPowActive && string.Equals(_lastPowActionType, "hps_mint", StringComparison.OrdinalIgnoreCase)))
            {
                _deferredAutoSignTransferId = transferId;
                AppendPowLog($"Assinatura de {transferId} adiada até o fim do PoW atual.");
                StartFlowPopup(popupId, "Assinatura pendente", $"Transferência {transferId} aguardando assinatura.", details);
            }
            else
            {
                _deferredAutoSignTransferId = transferId;
                if (IsPowActive && string.Equals(_lastPowActionType, "hps_mint", StringComparison.OrdinalIgnoreCase))
                {
                    AppendPowLog($"Assinatura de {transferId} recebida durante a mineração. Processando em paralelo ao PoW.");
                    StartFlowPopup(popupId, "Assinatura pendente", $"Transferência {transferId} em fila de assinatura paralela.", details);
                }
                else
                {
                    StartFlowPopup(popupId, "Assinatura pendente", $"Assinando transferência {transferId}...", details);
                }
                EnsurePendingSignatureWorker();
            }
        }
        else
        {
            AppendPowLog($"Assinatura pendente para {transferId} (auto-assinatura desativada).");
            StartFlowPopup(
                TransferFlowPopupId(transferId, "signature"),
                "Assinatura pendente",
                $"Transferência aguardando assinatura ({transferId}).",
                $"Tipo: {transferType}\nRemetente: {sender}\nDestinatário: {receiver}");
        }

        return transferId;
    }

    private Task SignNextPendingTransferAsync()
    {
        if (_pendingMinerTransfers.Count == 0)
        {
            TransferStatus = "Sem pendências de assinatura.";
            return Task.CompletedTask;
        }
        var transferId = _pendingMinerTransfers.Keys.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(transferId))
        {
            TransferStatus = "Sem pendências de assinatura.";
            return Task.CompletedTask;
        }
        return SignTransferByIdAsync(transferId);
    }

    private void OpenContractAnalyzer()
    {
        if (_owner is null || SelectedContract is null)
        {
            return;
        }

        _pendingTransfersByContract.TryGetValue(SelectedContract.ContractId, out var pendingInfo);
        if (pendingInfo is not null)
        {
            _pendingTransferId = pendingInfo.TransferId;
            _pendingTransferType = pendingInfo.TransferType;
            RaiseCommandCanExecuteChanged();
        }

        var window = new ContractAnalyzerWindow();
        window.SetContent(
            SelectedContract,
            pendingInfo,
            () => _ = AcceptTransferAsync(),
            () => _ = RejectTransferAsync(),
            () => _ = RenounceTransferAsync()
        );
        window.ShowDialog(_owner);
    }

    private async Task AcceptTransferAsync()
    {
        if (string.IsNullOrWhiteSpace(_pendingTransferId))
        {
            return;
        }

        TransferStatus = "Aceitando transferência...";
        var pending = SelectedPendingTransfer ?? PendingTransfers.FirstOrDefault(p => p.TransferId == _pendingTransferId);
        if (pending is not null)
        {
            var details = $"Transferência: {pending.TransferId}\nTipo: {pending.TransferType}\nDe: {pending.OriginalOwner}\nPara: {pending.TargetUser}";
            StartImportantFlow("Transferência", "Aceitando transferência...", details, "transfer");
        }
        if (string.Equals(_pendingTransferType, "hps_transfer", StringComparison.OrdinalIgnoreCase))
        {
            _pendingTransferAction = "accept";
            await RunPowOrHpsAsync(
                "contract_transfer",
                () => RequestPowChallengeAsync("contract_transfer"),
                payment => _socketClient.EmitAsync("accept_hps_transfer", new
                {
                    transfer_id = _pendingTransferId,
                    pow_nonce = string.Empty,
                    hashrate_observed = 0.0,
                    hps_payment = payment.Payload
                }),
                null
            );
            return;
        }
        if (string.Equals(_pendingTransferType, "content_repair", StringComparison.OrdinalIgnoreCase))
        {
            TransferStatus = "Preparando reparo do conteúdo...";
            await _socketClient.EmitAsync("get_content_repair_payload", new { transfer_id = _pendingTransferId });
            return;
        }

        _pendingTransferAction = "accept";
        await _socketClient.EmitAsync("get_transfer_payload", new { transfer_id = _pendingTransferId });
    }

    private async Task RejectTransferAsync()
    {
        if (string.IsNullOrWhiteSpace(_pendingTransferId))
        {
            return;
        }

        if (string.Equals(_pendingTransferType, "content_repair", StringComparison.OrdinalIgnoreCase))
        {
            TransferStatus = "Reparo de conteúdo não pode ser rejeitado por aqui.";
            return;
        }

        TransferStatus = "Rejeitando transferência...";
        StartImportantFlow("Transferência", "Rejeitando transferência...", $"Transferência: {_pendingTransferId}", "transfer");
        _pendingTransferAction = "reject";
        await RunPowOrHpsAsync(
            "contract_transfer",
            () => RequestPowChallengeAsync("contract_transfer"),
            payment => _socketClient.EmitAsync("reject_transfer", new
            {
                transfer_id = _pendingTransferId,
                pow_nonce = string.Empty,
                hashrate_observed = 0.0,
                hps_payment = payment.Payload
            }),
            null
        );
    }

    private async Task RenounceTransferAsync()
    {
        if (string.IsNullOrWhiteSpace(_pendingTransferId))
        {
            return;
        }

        if (string.Equals(_pendingTransferType, "content_repair", StringComparison.OrdinalIgnoreCase))
        {
            TransferStatus = "Reparo de conteúdo não pode ser renunciado por aqui.";
            return;
        }

        TransferStatus = "Renunciando transferência...";
        StartImportantFlow("Transferência", "Renunciando transferência...", $"Transferência: {_pendingTransferId}", "transfer");
        _pendingTransferAction = "renounce";
        await RunPowOrHpsAsync(
            "contract_transfer",
            () => RequestPowChallengeAsync("contract_transfer"),
            payment => _socketClient.EmitAsync("renounce_transfer", new
            {
                transfer_id = _pendingTransferId,
                pow_nonce = string.Empty,
                hashrate_observed = 0.0,
                hps_payment = payment.Payload
            }),
            null
        );
    }

    private async Task AcceptInventoryRequestAsync()
    {
        if (SelectedInventoryRequest is null || string.IsNullOrWhiteSpace(SelectedInventoryRequest.TransferId))
        {
            return;
        }

        InventoryStatus = "Aceitando solicitação de inventório...";
        var transferId = SelectedInventoryRequest.TransferId;
        await _socketClient.EmitAsync("accept_inventory_transfer", new
        {
            transfer_id = transferId
        });
        _inventoryRequests.Remove(SelectedInventoryRequest);
        SelectedInventoryRequest = null;
    }

    private async Task RejectInventoryRequestAsync()
    {
        if (SelectedInventoryRequest is null || string.IsNullOrWhiteSpace(SelectedInventoryRequest.TransferId))
        {
            return;
        }

        InventoryStatus = "Rejeitando solicitação de inventório...";
        var transferId = SelectedInventoryRequest.TransferId;
        await _socketClient.EmitAsync("reject_inventory_transfer", new
        {
            transfer_id = transferId
        });
        _inventoryRequests.Remove(SelectedInventoryRequest);
        SelectedInventoryRequest = null;
    }

    private async Task UploadContentBytesAsync(string title, string description, string mimeType, byte[] content, string? expectedHash = null)
    {
        await RunOnUiAsync(() =>
        {
            UploadTitle = string.IsNullOrWhiteSpace(title) ? UploadTitle : title;
            UploadDescription = description;
            UploadMimeType = string.IsNullOrWhiteSpace(mimeType) ? UploadMimeType : mimeType;
        }).ConfigureAwait(false);

        if (_privateKey is null)
        {
            await RunOnUiAsync(() => UploadStatus = "Chave privada não disponível.").ConfigureAwait(false);
            return;
        }

        var contentHash = _contentService.ComputeSha256HexBytes(content);
        if (!string.IsNullOrWhiteSpace(expectedHash) &&
            !string.Equals(contentHash, expectedHash, StringComparison.OrdinalIgnoreCase))
        {
            await RunOnUiAsync(() => UploadStatus = "Hash do conteúdo não corresponde ao esperado.").ConfigureAwait(false);
            return;
        }
        var signature = _privateKey.SignData(content, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var signatureB64 = Convert.ToBase64String(signature);
        var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));

        var contractText = _contentService.BuildContractTemplate("upload_file", new Dictionary<string, string>
        {
            { "FILE_NAME", title },
            { "FILE_SIZE", content.Length.ToString() },
            { "FILE_HASH", contentHash },
            { "TITLE", title },
            { "MIME", mimeType },
            { "DESCRIPTION", description },
            { "PUBLIC_KEY", publicKeyB64 }
        });

        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);
        var fullContent = _contentService.CombineBytes(content, Encoding.UTF8.GetBytes(signedContract));
        var fullContentB64 = Convert.ToBase64String(fullContent);

        _contentService.SaveContentToStorage(contentHash, content, title, description, mimeType, signatureB64, publicKeyB64, User);
        SaveLocalPublishedContract("upload_file", contentHash, string.Empty, signedContract);
        LoadLocalInventory();

        _pendingUpload = new PendingUpload(
            contentHash,
            title,
            description,
            mimeType,
            content.Length,
            signatureB64,
            publicKeyB64,
            fullContentB64
        );

        await RunOnUiAsync(() => UploadStatus = "Preparando upload...").ConfigureAwait(false);
        await RunPowOrHpsAsync(
            "upload",
            () =>
            {
                RunOnUi(() => UploadStatus = "Solicitando PoW para upload...");
                return RequestPowChallengeAsync("upload");
            },
            payment =>
            {
                RunOnUi(() => UploadStatus = "Enviando upload com pagamento HPS...");
                return SubmitPendingUploadAsync(0, 0.0, payment.Payload);
            },
            null
        );
    }

    private async Task UploadTransferContentAsync(string title, string description, string mimeType, byte[] content)
    {
        if (_privateKey is null)
        {
            TransferStatus = "Chave privada não disponível.";
            return;
        }
        var pending = SelectedPendingTransfer;
        if (pending is null && !string.IsNullOrWhiteSpace(_pendingTransferId))
        {
            pending = PendingTransfers.FirstOrDefault(p => p.TransferId == _pendingTransferId);
        }
        if (pending is null)
        {
            TransferStatus = "Pendência não encontrada.";
            return;
        }

        var contentHash = _contentService.ComputeSha256HexBytes(content);
        if (!string.IsNullOrWhiteSpace(pending.ContentHash) &&
            !string.Equals(contentHash, pending.ContentHash, StringComparison.OrdinalIgnoreCase))
        {
            TransferStatus = "Hash do conteúdo não corresponde à pendência.";
            return;
        }

        var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));
        var details = new Dictionary<string, string>
        {
            { "TRANSFER_TO", User },
            { "TRANSFER_TYPE", pending.TransferType },
            { "FILE_HASH", contentHash },
            { "CONTENT_HASH", contentHash },
            { "FILE_NAME", title },
            { "FILE_SIZE", content.Length.ToString() },
            { "TITLE", title },
            { "MIME", mimeType },
            { "DESCRIPTION", description },
            { "PUBLIC_KEY", publicKeyB64 }
        };
        if (!string.IsNullOrWhiteSpace(pending.Domain))
        {
            details["DOMAIN"] = pending.Domain;
        }
        if (!string.IsNullOrWhiteSpace(pending.AppName))
        {
            details["APP"] = pending.AppName;
        }

        var actionType = "transfer_content";
        if (string.Equals(pending.TransferType, "api_app", StringComparison.OrdinalIgnoreCase))
        {
            actionType = "transfer_api_app";
        }
        else if (string.Equals(pending.TransferType, "domain", StringComparison.OrdinalIgnoreCase))
        {
            actionType = "transfer_domain";
        }

        var contractText = _contentService.BuildContractTemplate(actionType, details);
        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);
        var fullContent = _contentService.CombineBytes(content, Encoding.UTF8.GetBytes(signedContract));
        var fullContentB64 = Convert.ToBase64String(fullContent);

        var signature = _privateKey.SignData(content, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var signatureB64 = Convert.ToBase64String(signature);

        _contentService.SaveContentToStorage(contentHash, content, title, description, mimeType, signatureB64, publicKeyB64, User);
        SaveLocalPublishedContract(actionType, contentHash, pending.TransferType.Equals("domain", StringComparison.OrdinalIgnoreCase) ? pending.Domain : string.Empty, signedContract);
        LoadLocalInventory();

        _pendingUpload = new PendingUpload(
            contentHash,
            title,
            description,
            mimeType,
            content.Length,
            signatureB64,
            publicKeyB64,
            fullContentB64
        );

        TransferStatus = "Preparando transferência...";
        _pendingTransferUploadId = pending.TransferId;
        StartImportantFlow(
            "Transferência",
            "Preparando transferência...",
            $"Transferência: {pending.TransferId}\nTipo: {pending.TransferType}\nDe: {pending.OriginalOwner}\nPara: {pending.TargetUser}",
            "transfer"
        );
        await RunPowOrHpsAsync(
            "upload",
            () =>
            {
                TransferStatus = "Enviando transferência (PoW)...";
                return RequestPowChallengeAsync("upload");
            },
            payment =>
            {
                TransferStatus = "Enviando transferência com pagamento HPS...";
                return SubmitPendingUploadAsync(0, 0.0, payment.Payload);
            },
            null
        );
    }

    private async Task SyncClientFilesAsync()
    {
        var contractContentHashes = _database.LoadContractSummaries()
            .Select(c => c.contentHash)
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var files = _database.LoadContentSummaries()
            .Select(f => new
            {
                content_hash = f.contentHash,
                file_name = f.fileName,
                file_size = f.size,
                published = _knownPublishedContentHashes.Contains(f.contentHash) || contractContentHashes.Contains(f.contentHash)
            })
            .ToList();
        await _socketClient.EmitAsync("sync_client_files", new { files });
    }

    private async Task SyncClientDnsFilesAsync()
    {
        var dnsFiles = _database.LoadDdnsSummaries()
            .Select(d => new { domain = d.domain, ddns_hash = d.ddnsHash })
            .ToList();
        await _socketClient.EmitAsync("sync_client_dns_files", new { dns_files = dnsFiles });
    }

    private async Task SyncClientContractsAsync()
    {
        var contracts = _database.LoadContractSummaries()
            .Select(c => new { contract_id = c.contractId, content_hash = c.contentHash, domain = c.domain })
            .ToList();
        await _socketClient.EmitAsync("sync_client_contracts", new { contracts });
    }

    private void ScheduleClientPropagationSync()
    {
        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            return;
        }
        if (Interlocked.CompareExchange(ref _clientPropagationSyncScheduled, 1, 0) != 0)
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(250).ConfigureAwait(false);
                if (!IsLoggedIn || !_socketClient.IsConnected)
                {
                    return;
                }
                await SyncClientFilesAsync().ConfigureAwait(false);
                await SyncClientDnsFilesAsync().ConfigureAwait(false);
                await SyncClientContractsAsync().ConfigureAwait(false);
            }
            catch
            {
                // Best-effort propagation refresh; the regular login sync will retry later.
            }
            finally
            {
                Interlocked.Exchange(ref _clientPropagationSyncScheduled, 0);
            }
        });
    }

    private async Task SendContentToServerAsync(string contentHash)
    {
        var metadata = _database.LoadContentMetadata(contentHash);
        if (metadata is null)
        {
            await EmitContentFromClientFailureAsync(contentHash, "missing_local_metadata");
            return;
        }

        var (filePath, title, description, mimeType, username, signature, publicKey, verified) = metadata.Value;
        if (!File.Exists(filePath))
        {
            await EmitContentFromClientFailureAsync(contentHash, "missing_local_file");
            return;
        }
        if (string.IsNullOrWhiteSpace(signature) || string.IsNullOrWhiteSpace(publicKey))
        {
            await EmitContentFromClientFailureAsync(contentHash, "missing_local_signature");
            return;
        }

        var localContent = _contentService.TryLoadLocalContent(contentHash);
        if (localContent is null)
        {
            await EmitContentFromClientFailureAsync(contentHash, "local_decrypt_failed");
            return;
        }
        var content = localContent.Data;
        var actualHash = _contentService.ComputeSha256HexBytes(content);
        if (!string.Equals(actualHash, contentHash, StringComparison.OrdinalIgnoreCase))
        {
            await EmitContentFromClientFailureAsync(contentHash, "local_hash_mismatch");
            return;
        }
        var contracts = BuildLocalContractPayloadsForContent(contentHash);

        await _socketClient.EmitAsync("content_from_client", new
        {
            content_hash = contentHash,
            content = Convert.ToBase64String(content),
            title,
            description,
            mime_type = mimeType,
            username,
            signature,
            public_key = publicKey,
            verified,
            contracts
        });
    }

    private List<object> BuildLocalContractPayloadsForContent(string contentHash)
    {
        return _database.LoadContractSummaries()
            .Where(c => string.Equals(c.contentHash, contentHash, StringComparison.OrdinalIgnoreCase))
            .Select(c => _database.LoadContractRecord(c.contractId))
            .Where(c => c is not null && !string.IsNullOrWhiteSpace(c.ContractContent))
            .Select(c => (object)new
            {
                contract_id = c!.ContractId,
                contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(c.ContractContent)),
                action_type = c.ActionType,
                content_hash = string.IsNullOrWhiteSpace(c.ContentHash) ? contentHash : c.ContentHash,
                domain = c.Domain,
                username = c.Username,
                signature = c.Signature,
                verified = c.Verified == "Sim",
                timestamp = c.Timestamp
            })
            .ToList();
    }

    private async Task EmitContentFromClientFailureAsync(string contentHash, string reason)
    {
        if (!_socketClient.IsConnected)
        {
            return;
        }
        await _socketClient.EmitAsync("content_from_client_failure", new
        {
            content_hash = contentHash,
            reason
        });
    }

    private bool HasLocalContractForContent(string contentHash)
    {
        if (string.IsNullOrWhiteSpace(contentHash))
        {
            return false;
        }

        return _database.LoadContractSummaries()
            .Any(c => string.Equals(c.contentHash, contentHash, StringComparison.OrdinalIgnoreCase));
    }

    private async Task SyncKnownServersAsync()
    {
        var servers = KnownServers
            .Select(s => NormalizeServerAddressInput(s.Address))
            .Append(NormalizeServerAddressInput(ServerAddress))
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (servers.Length == 0 || !_socketClient.IsConnected)
        {
            return;
        }
        await _socketClient.EmitAsync("sync_servers", new { servers });
    }

    private async Task SendDdnsToServerAsync(string domain)
    {
        var record = _database.LoadDdnsRecord(domain);
        if (record is null)
        {
            return;
        }

        var (ddnsHash, contentHash, username, verified, signature, publicKey) = record.Value;
        var ddnsBytes = _contentService.TryLoadDdnsContent(ddnsHash);
        if (ddnsBytes is null)
        {
            return;
        }

        await _socketClient.EmitAsync("ddns_from_client", new
        {
            domain,
            ddns_content = Convert.ToBase64String(ddnsBytes),
            content_hash = contentHash,
            username,
            signature,
            public_key = publicKey,
            verified
        });
    }

    private async Task SendContractToServerAsync(string contractId)
    {
        var record = _database.LoadContractRecord(contractId);
        if (record is null || string.IsNullOrWhiteSpace(record.ContractContent))
        {
            return;
        }

        await _socketClient.EmitAsync("contract_from_client", new
        {
            contract_id = contractId,
            contract_content = Convert.ToBase64String(Encoding.UTF8.GetBytes(record.ContractContent)),
            action_type = record.ActionType,
            content_hash = record.ContentHash,
            domain = record.Domain,
            username = record.Username,
            signature = record.Signature,
            verified = record.Verified == "Sim"
        });
    }

    private async Task JoinNetworkAsync()
    {
        if (string.IsNullOrWhiteSpace(User))
        {
            return;
        }

        var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));
        await _socketClient.EmitAsync("join_network", new
        {
            node_id = NodeId,
            address = $"client_{ClientId}",
            public_key = publicKeyB64,
            username = User,
            node_type = _nodeType,
            client_identifier = ClientId
        });
    }

    private static string GenerateToken()
    {
        var bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        var token = Convert.ToBase64String(bytes);
        return token.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static string BuildDatabaseSnapshotMutexName(string dbPath)
    {
        var normalized = Path.GetFullPath(dbPath).ToLowerInvariant();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        return "Local\\HpsBrowserDbSnapshot_" + Convert.ToHexString(hash[..8]);
    }

    private static readonly Regex TransferTitleRegex = new(@"\(HPS!transfer\)\{type=([^,}]+),\s*to=([^,}]+)(?:,\s*app=([^}]+))?\}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex ApiAppTitleRegex = new(@"\(HPS!api\)\{app\}:\{""([^""]+)""\}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private const string DnsChangeTitle = "(HPS!dns_change){change_dns_owner=true, proceed=true}";

    private sealed record ApiAppRequest(
        string AppName,
        string Title,
        string CurrentHash,
        ContentSecurityInfo ContentInfo,
        byte[] ContentBytes,
        string MimeType,
        string? FallbackHash
    );

    private static (string TransferType, string TransferTo, string TransferApp) ParseTransferTitle(string title)
    {
        if (string.IsNullOrWhiteSpace(title))
        {
            return (string.Empty, string.Empty, string.Empty);
        }
        var match = TransferTitleRegex.Match(title);
        if (!match.Success)
        {
            return (string.Empty, string.Empty, string.Empty);
        }
        var transferType = match.Groups.Count > 1 ? match.Groups[1].Value.Trim() : string.Empty;
        var transferTo = match.Groups.Count > 2 ? match.Groups[2].Value.Trim() : string.Empty;
        var transferApp = match.Groups.Count > 3 ? match.Groups[3].Value.Trim() : string.Empty;
        return (transferType, transferTo, transferApp);
    }

    private static string ExtractApiAppName(string title)
    {
        if (string.IsNullOrWhiteSpace(title))
        {
            return string.Empty;
        }
        var match = ApiAppTitleRegex.Match(title);
        if (!match.Success || match.Groups.Count < 2)
        {
            return string.Empty;
        }
        return match.Groups[1].Value.Trim();
    }

    private async Task RequestApiAppVersionsAsync(string appName, string title, string currentHash, ContentSecurityInfo info, byte[] contentBytes, string mimeType, string? fallbackHash)
    {
        if (!_socketClient.IsConnected)
        {
            RenderContentFallback(info, contentBytes, currentHash, mimeType);
            return;
        }
        var requestId = Guid.NewGuid().ToString();
        _pendingApiAppRequests[requestId] = new ApiAppRequest(appName, title, currentHash, info, contentBytes, mimeType, fallbackHash);
        await _socketClient.EmitAsync("get_api_app_versions", new
        {
            request_id = requestId,
            title,
            app_name = appName
        });
    }

    private async Task RequestContentByHashAsync(string contentHash)
    {
        if (string.IsNullOrWhiteSpace(contentHash))
        {
            return;
        }
        StartImportantFlow(
            "Abertura de conteúdo",
            "Solicitando conteúdo ao servidor...",
            $"Hash: {contentHash}\nServidor: {ServerAddress}",
            "content");
        await _socketClient.EmitAsync("request_content", new { content_hash = contentHash });
    }

    private void ShowCriticalBrowserError(string code, string title, string message, string targetType = "", string targetId = "", string reason = "")
    {
        CriticalBrowserErrorCode = string.IsNullOrWhiteSpace(code) ? "HPS-CRITICAL" : code;
        CriticalBrowserErrorTitle = title;
        CriticalBrowserErrorMessage = message;
        _criticalBrowserTargetType = targetType;
        _criticalBrowserTargetId = targetId;
        _criticalBrowserReason = reason;
        CanResolveCriticalBrowserError = IsCertifiableContractReason(reason) &&
                                         !string.IsNullOrWhiteSpace(targetType) &&
                                         !string.IsNullOrWhiteSpace(targetId) &&
                                         _privateKey is not null &&
                                         IsLoggedIn &&
                                         _socketClient.IsConnected;
        IsCriticalBrowserErrorVisible = true;
        IsBrowserImageVisible = false;
        IsBrowserTextVisible = true;
        (ResolveCriticalBrowserErrorCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
    }

    private static bool IsCertifiableContractReason(string reason)
    {
        return string.Equals(reason, "missing_contract", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(reason, "invalid_contract", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(reason, "invalid_signature", StringComparison.OrdinalIgnoreCase);
    }

    private void CloseCriticalBrowserError()
    {
        IsCriticalBrowserErrorVisible = false;
    }

    private async Task ResolveCriticalBrowserErrorAsync()
    {
        if (!CanResolveCriticalBrowserError ||
            _privateKey is null ||
            string.IsNullOrWhiteSpace(_criticalBrowserTargetType) ||
            string.IsNullOrWhiteSpace(_criticalBrowserTargetId))
        {
            return;
        }

        var details = new Dictionary<string, string>
        {
            ["TARGET_TYPE"] = _criticalBrowserTargetType,
            ["TARGET_ID"] = _criticalBrowserTargetId,
            ["REASON"] = string.IsNullOrWhiteSpace(_criticalBrowserReason) ? "missing_contract" : _criticalBrowserReason,
            ["PUBLIC_KEY"] = PublicKeyPem
        };
        if (_criticalBrowserTargetType == "content")
        {
            details["CONTENT_HASH"] = _criticalBrowserTargetId;
        }
        else if (_criticalBrowserTargetType == "domain")
        {
            details["DOMAIN"] = _criticalBrowserTargetId;
        }

        var contractText = _contentService.BuildContractTemplate("certify_contract", details);
        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);
        _pendingCriticalContractCertification = new PendingCriticalContractCertification(
            _criticalBrowserTargetType,
            _criticalBrowserTargetId,
            Convert.ToBase64String(Encoding.UTF8.GetBytes(signedContract)));
        CriticalBrowserErrorMessage = "Gerando prova de trabalho para certificar a pendência contratual...";
        await RequestPowChallengeAsync("contract_certify");
    }

    private void RenderContentFallback(ContentSecurityInfo info, byte[] contentBytes, string contentHash, string mimeType)
    {
        _lastContentInfo = info;
        _lastContentHash = contentHash;
        RenderContent(contentBytes, info.Title, info.Description, mimeType);
        if (!string.IsNullOrWhiteSpace(contentHash))
        {
            _contentService.SaveContentToStorage(
                contentHash,
                contentBytes,
                info.Title,
                info.Description,
                mimeType,
                info.Signature,
                info.PublicKey,
                info.Username
            );
            IncrementContentDownloaded(contentHash);
            LoadLocalInventory();
        }
    }

    private async Task EmitContractViolationAsync(string violationType, string contentHash, string domain, string reason)
    {
        if (!_socketClient.IsConnected)
        {
            return;
        }
        await _socketClient.EmitAsync("contract_violation", new
        {
            violation_type = violationType,
            content_hash = contentHash,
            domain,
            reason
        });
    }

    private static (string Domain, string NewOwner, string Error) ParseDnsChangeManifest(byte[] content)
    {
        var text = Encoding.UTF8.GetString(content);
        if (!text.StartsWith("# HSYST P2P SERVICE", StringComparison.Ordinal))
        {
            return (string.Empty, string.Empty, "Arquivo DNS change inválido: cabeçalho HSYST ausente.");
        }
        if (!text.Contains("### MODIFY:", StringComparison.Ordinal) || !text.Contains("# change_dns_owner = true", StringComparison.Ordinal))
        {
            return (string.Empty, string.Empty, "Arquivo DNS change inválido: seção MODIFY ausente.");
        }

        var domain = string.Empty;
        var newOwner = string.Empty;
        var inDns = false;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line == "### DNS:")
            {
                inDns = true;
                continue;
            }
            if (line == "### :END DNS")
            {
                inDns = false;
                continue;
            }
            if (inDns && line.StartsWith("# NEW_DNAME:", StringComparison.Ordinal))
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2)
                {
                    domain = parts[1].Trim();
                }
            }
            if (line.StartsWith("# NEW_DOWNER:", StringComparison.Ordinal))
            {
                var parts = line.Split('=', 2);
                if (parts.Length == 2)
                {
                    newOwner = parts[1].Trim();
                }
            }
        }

        if (string.IsNullOrWhiteSpace(domain) || string.IsNullOrWhiteSpace(newOwner))
        {
            return (string.Empty, string.Empty, "Arquivo DNS change inválido: domínio ou novo dono ausente.");
        }
        return (domain, newOwner, string.Empty);
    }

    private static string ComputeSha256Hex(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string GenerateNonceHex(int size)
    {
        if (size <= 0)
        {
            return string.Empty;
        }
        var bytes = new byte[size];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private async Task ReportContentTamperAsync(string contentHash, string reason)
    {
        if (string.IsNullOrWhiteSpace(contentHash) || !_socketClient.IsConnected)
        {
            return;
        }
        await _socketClient.EmitAsync("content_integrity_report", new
        {
            content_hash = contentHash,
            reason
        });
    }

    private async Task RefreshPendingTransfersAsync()
    {
        if (!_socketClient.IsConnected)
        {
            PendingTransferStatus = "Conecte-se à rede primeiro.";
            return;
        }
        PendingTransferStatus = "Atualizando pendências...";
        await _socketClient.EmitAsync("get_pending_transfers", new { });
        await RequestMinerPendingTransfersAsync();
    }

    private async Task RequestMinerPendingTransfersAsync()
    {
        if (!_socketClient.IsConnected)
        {
            return;
        }
        await _socketClient.EmitAsync("get_miner_pending_transfers", new { });
    }

    private async Task ResolveDnsAsync()
    {
        if (string.IsNullOrWhiteSpace(DnsDomain))
        {
            return;
        }

        if (!_socketClient.IsConnected)
        {
            DnsStatus = "Conecte-se à rede primeiro.";
            return;
        }

        var domain = DnsDomain.Trim().ToLowerInvariant();
        DnsStatus = "Resolvendo DNS...";
        StartImportantFlow("Resolução DNS", "Resolvendo DNS...", $"Domínio: {domain}", "dns");
        UpdateImportantFlowStatus("Consultando a rede e validando o vínculo do domínio...");
        await _socketClient.EmitAsync("resolve_dns", new { domain });
    }

    private async Task SelectDnsFileAsync()
    {
        if (_owner is null)
        {
            return;
        }

        var path = await _fileDialogService.OpenFileAsync(_owner, "Selecionar arquivo", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return;
        }

        var bytes = await File.ReadAllBytesAsync(path);
        DnsContentHash = _contentService.ComputeSha256HexBytes(bytes);
    }

    private async Task NavigateAsync()
    {
        if (string.IsNullOrWhiteSpace(BrowserUrl))
        {
            return;
        }

        await NavigateToAsync(BrowserUrl.Trim(), true);
    }

    private void OpenSearchWindow()
    {
        if (_owner is null)
        {
            return;
        }

        if (_searchWindow is null || !_searchWindow.IsVisible)
        {
            _searchWindow = new SearchWindow
            {
                DataContext = this
            };
            _searchWindow.Show(_owner);
        }
        else
        {
            _searchWindow.Activate();
        }
    }

    private async Task SearchContentAsync()
    {
        if (!_socketClient.IsConnected)
        {
            SearchStatus = "Conecte-se à rede primeiro.";
            return;
        }

        var query = SearchQuery?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(query))
        {
            SearchStatus = "Informe um termo de busca.";
            return;
        }

        SearchResults.Clear();
        SearchStatus = $"Buscando por: '{query}'";
        var contentType = string.Equals(SearchContentType, "all", StringComparison.OrdinalIgnoreCase)
            ? string.Empty
            : SearchContentType;
        await _socketClient.EmitAsync("search_content", new
        {
            query,
            content_type = contentType,
            sort_by = SearchSortBy,
            limit = 50,
            offset = 0
        });
    }

    private void ClearSearch()
    {
        SearchQuery = string.Empty;
        SearchResults.Clear();
        SearchStatus = string.Empty;
    }

    private async Task CopySearchHashAsync()
    {
        if (SelectedSearchResult is null)
        {
            return;
        }
        var clipboard = ResolveClipboard();
        if (clipboard is null)
        {
            SearchStatus = "Área de transferência indisponível.";
            return;
        }
        try
        {
            await clipboard.SetTextAsync(SelectedSearchResult.ContentHash);
            SearchStatus = "Hash copiado para a área de transferência.";
        }
        catch (Exception ex)
        {
            SearchStatus = $"Falha ao copiar hash: {ex.Message}";
        }
    }

    private void OpenSelectedSearchResult()
    {
        if (SelectedSearchResult is null)
        {
            return;
        }
        var url = $"hps://{SelectedSearchResult.ContentHash}";
        BrowserUrl = url;
        _ = NavigateToAsync(url, true);
    }

    private async Task NavigateToAsync(string url, bool addHistory)
    {
        if (addHistory)
        {
            AddToHistory(url);
        }

        var trimmed = url.Trim();
        if (!trimmed.Contains("://", StringComparison.Ordinal))
        {
            if (LooksLikeHash(trimmed))
            {
                trimmed = $"hps://{trimmed}";
            }
            else
            {
                DnsDomain = trimmed.ToLowerInvariant();
                await ResolveDnsAsync();
                return;
            }
        }

        if (trimmed.StartsWith("hps://dns:", StringComparison.OrdinalIgnoreCase))
        {
            var domain = trimmed.Substring("hps://dns:".Length);
            DnsDomain = domain;
            await ResolveDnsAsync();
            return;
        }

        if (trimmed.StartsWith("hps://", StringComparison.OrdinalIgnoreCase))
        {
            var contentHash = trimmed.Substring("hps://".Length);
            if (!LooksLikeHash(contentHash) && !string.IsNullOrWhiteSpace(contentHash))
            {
                DnsDomain = contentHash.ToLowerInvariant();
                await ResolveDnsAsync();
                return;
            }
            if (!string.IsNullOrWhiteSpace(contentHash))
            {
                var localContent = _contentService.TryLoadLocalContent(contentHash);
                if (localContent is not null)
                {
                    _lastContentHash = contentHash;
                    if (!HasLocalContractForContent(contentHash))
                    {
                        if (_socketClient.IsConnected)
                        {
                            await RequestContentByHashAsync(contentHash);
                            return;
                        }
                        BrowserContent = "Conteúdo local bloqueado: contrato ausente.";
                        ShowCriticalBrowserError(
                            "HPS-MISSING-CONTRACT",
                            "Arquivo sem contrato",
                            $"O arquivo local {contentHash} existe no cache, mas nenhum contrato local foi encontrado para certificar o acesso.",
                            "content",
                            contentHash,
                            "missing_contract");
                        return;
                    }
                    var metadata = _database.LoadContentMetadata(contentHash);
                    if (metadata is not null)
                    {
                        _lastContentPublicKey = metadata.Value.publicKey;
                        _lastContentSignatureValid = metadata.Value.verified;
                        var contracts = Contracts.Where(c => string.Equals(c.ContentHash, contentHash, StringComparison.OrdinalIgnoreCase))
                            .Select(c => $"{c.ActionType} | {c.ContractId}")
                            .ToList();
                        _lastContentInfo = new ContentSecurityInfo(
                            metadata.Value.title,
                            metadata.Value.description,
                            metadata.Value.username,
                            metadata.Value.username,
                            contentHash,
                            metadata.Value.mimeType,
                            metadata.Value.signature,
                            metadata.Value.publicKey,
                            metadata.Value.verified,
                            0,
                            contracts,
                            string.Empty
                        );
                    }
                    RenderContent(localContent.Data, localContent.Title, localContent.Description, localContent.MimeType);
                    return;
                }
                await RequestContentByHashAsync(contentHash);
                return;
            }
        }

        BrowserContent = "URL não suportada. Use hps://<hash> ou hps://dns:<dominio>.";
    }

    private static bool LooksLikeHash(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 64)
        {
            return false;
        }
        return value.All(c =>
            (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'));
    }

    private async Task ShowBrowserSecurityAsync()
    {
        if (_owner is null)
        {
            return;
        }

        if (_lastContentInfo is null || string.IsNullOrWhiteSpace(_lastContentHash))
        {
            await _promptService.ConfirmAsync(_owner, "Segurança do Conteúdo", "Nenhum conteúdo carregado.", "OK", "Fechar");
            return;
        }

        var window = new ContentSecurityWindow();
        window.SetContent(_lastContentInfo, _lastContentBytes?.Length ?? 0);
        await window.ShowDialog(_owner);
    }

    private async Task ShowDnsSecurityAsync()
    {
        if (_owner is null)
        {
            return;
        }

        if (_lastDomainInfo is null)
        {
            var domain = SelectedDnsRecord?.Domain ?? DnsDomain;
            if (string.IsNullOrWhiteSpace(domain))
            {
                await _promptService.ConfirmAsync(_owner, "Segurança DNS", "Nenhum domínio selecionado.", "OK", "Fechar");
                return;
            }
            var record = _database.LoadDdnsRecord(domain);
            if (record is null)
            {
                await _promptService.ConfirmAsync(_owner, "Segurança DNS", "Registro DNS não encontrado localmente.", "OK", "Fechar");
                return;
            }
            _lastDomainInfo = new DomainSecurityInfo(
                domain,
                record.Value.contentHash,
                record.Value.username,
                record.Value.username,
                record.Value.verified,
                record.Value.signature,
                new List<string>(),
                string.Empty
            );
        }
        var window = new DomainSecurityWindow();
        window.SetContent(_lastDomainInfo);
        await window.ShowDialog(_owner);
    }

    private void AddToHistory(string url)
    {
        if (_historyIndex >= 0 && _historyIndex < _history.Count && _history[_historyIndex] == url)
        {
            return;
        }

        if (_historyIndex < _history.Count - 1)
        {
            _history.RemoveRange(_historyIndex + 1, _history.Count - _historyIndex - 1);
        }

        _history.Add(url);
        _historyIndex = _history.Count - 1;
        RaiseCommandCanExecuteChanged();
    }

    private void RenderContent(byte[] data, string title, string description, string mimeType)
    {
        _lastContentBytes = data;
        _lastContentTitle = title ?? string.Empty;
        _lastContentMime = mimeType ?? string.Empty;
        RaiseCommandCanExecuteChanged();

        var hasText = !string.IsNullOrWhiteSpace(title) || !string.IsNullOrWhiteSpace(description);
        var isText = !string.IsNullOrWhiteSpace(mimeType) &&
                     mimeType.StartsWith("text/", StringComparison.OrdinalIgnoreCase);
        if (!isText)
        {
            isText = IsLikelyText(data);
        }

        if (isText)
        {
            BrowserImage = null;
            BrowserContent = data.Length <= MaxInlineTextBytes
                ? Encoding.UTF8.GetString(data)
                : $"Conteúdo textual grande ({data.Length / 1024 / 1024.0:0.##} MB). Use Salvar Conteúdo para abrir fora do Browser.";
        }
        else if (!string.IsNullOrWhiteSpace(mimeType) && mimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
        {
            using var stream = new MemoryStream(data);
            BrowserImage = Bitmap.DecodeToWidth(stream, 1024);
            BrowserContent = "Imagem carregada.";
            hasText = true;
        }
        else
        {
            BrowserImage = null;
            BrowserContent = $"Conteúdo binário ({mimeType}).";
        }

        IsBrowserImageVisible = BrowserImage is not null;
        IsBrowserTextVisible = hasText || !string.IsNullOrWhiteSpace(BrowserContent);
    }

    private ContentResponseValidationResult ValidateContentResponseData(string contentB64, string contentHash, string username, string signatureB64, string publicKey)
    {
        if (!TryDecodeBase64Flexible(contentB64, out var data))
        {
            return new ContentResponseValidationResult(false, Array.Empty<byte>(), false, "Falha ao decodificar conteúdo.", string.Empty, string.Empty, string.Empty, string.Empty);
        }

        var isSystemMessage = string.Equals(username, "system", StringComparison.OrdinalIgnoreCase);
        if (isSystemMessage)
        {
            return new ContentResponseValidationResult(true, data, false, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
        }

        if (!string.IsNullOrWhiteSpace(contentHash))
        {
            var computedHash = _contentService.ComputeSha256HexBytes(data);
            if (!string.Equals(computedHash, contentHash, StringComparison.OrdinalIgnoreCase))
            {
                return new ContentResponseValidationResult(
                    false,
                    data,
                    false,
                    "Conteúdo adulterado: hash inválido.",
                    "HPS-CONTENT-TAMPERED",
                    "Arquivo adulterado",
                    $"O hash calculado não corresponde ao hash solicitado ({contentHash}). O conteúdo foi bloqueado.",
                    "content_tampered");
            }
        }

        if (string.IsNullOrWhiteSpace(signatureB64) || string.IsNullOrWhiteSpace(publicKey))
        {
            return new ContentResponseValidationResult(
                false,
                data,
                false,
                "Conteúdo sem assinatura ou chave pública.",
                "HPS-MISSING-SIGNATURE",
                "Arquivo sem prova criptográfica",
                $"O arquivo {contentHash} não tem assinatura ou chave pública suficiente para validação.",
                "missing_signature");
        }

        byte[] signatureBytes;
        try
        {
            signatureBytes = Convert.FromBase64String(signatureB64);
        }
        catch
        {
            return new ContentResponseValidationResult(
                false,
                data,
                false,
                "Assinatura inválida para o conteúdo.",
                "HPS-CONTENT-SIGNATURE",
                "Assinatura inválida",
                $"A assinatura do arquivo {contentHash} não está em Base64 válido.",
                "content_signature_invalid");
        }

        var rsa = CryptoUtils.LoadPublicKey(publicKey);
        var signatureOk = false;
        if (rsa is not null)
        {
            signatureOk = CryptoUtils.VerifySignature(rsa, data, signatureBytes);
            if (!signatureOk)
            {
                signatureOk = CryptoUtils.VerifySignaturePssMax(rsa, data, signatureBytes);
            }
        }
        if (!signatureOk)
        {
            return new ContentResponseValidationResult(
                false,
                data,
                false,
                "Assinatura inválida para o conteúdo.",
                "HPS-CONTENT-SIGNATURE",
                "Assinatura inválida",
                $"A assinatura do arquivo {contentHash} não confere com a chave pública declarada.",
                "content_signature_invalid");
        }

        return new ContentResponseValidationResult(true, data, true, string.Empty, string.Empty, string.Empty, string.Empty, string.Empty);
    }

    private static bool IsLikelyText(byte[] data)
    {
        if (data.Length == 0 || data.Length > MaxTextProbeBytes)
        {
            return false;
        }

        var text = Encoding.UTF8.GetString(data);
        var printable = 0;
        var total = 0;
        foreach (var c in text)
        {
            total++;
            if (c == '\r' || c == '\n' || c == '\t')
            {
                printable++;
                continue;
            }
            if (c >= ' ' && c <= '\u007E')
            {
                printable++;
            }
        }
        return total > 0 && printable / (double)total > 0.85;
    }

    private static bool TryDecodeBase64Flexible(string input, out byte[] data)
    {
        data = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var trimmed = input.Trim();
        try
        {
            data = Convert.FromBase64String(trimmed);
            return true;
        }
        catch
        {
            // Try base64url.
        }

        var cleaned = trimmed.Replace('-', '+').Replace('_', '/');
        cleaned = cleaned.Replace("\n", "").Replace("\r", "").Replace(" ", "");
        var padding = cleaned.Length % 4;
        if (padding > 0)
        {
            cleaned = cleaned.PadRight(cleaned.Length + (4 - padding), '=');
        }

        try
        {
            data = Convert.FromBase64String(cleaned);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static List<string> ParseContractsList(JsonElement contractsProp)
    {
        var contracts = new List<string>();
        foreach (var contractElem in contractsProp.EnumerateArray())
        {
            if (contractElem.ValueKind != JsonValueKind.Object)
            {
                continue;
            }
            var action = contractElem.TryGetProperty("action_type", out var actionProp) ? actionProp.GetString() ?? string.Empty : string.Empty;
            var id = contractElem.TryGetProperty("contract_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            if (!string.IsNullOrWhiteSpace(action) || !string.IsNullOrWhiteSpace(id))
            {
                contracts.Add($"{action} | {id}".Trim());
            }
        }
        return contracts;
    }

    private async Task RequestContractsFromPayloadAsync(JsonElement contractsProp)
    {
        if (contractsProp.ValueKind != JsonValueKind.Array || !_socketClient.IsConnected)
        {
            return;
        }

        foreach (var contractElem in contractsProp.EnumerateArray())
        {
            if (contractElem.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var id = contractElem.TryGetProperty("contract_id", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
            var local = string.IsNullOrWhiteSpace(id) ? null : _database.LoadContractRecord(id);
            if (string.IsNullOrWhiteSpace(id) || (local is not null && !string.IsNullOrWhiteSpace(local.ContractContent)))
            {
                continue;
            }
            await _socketClient.EmitAsync("get_contract", new { contract_id = id });
        }
    }

    private void SaveContractsFromPayload(JsonElement contractsProp)
    {
        if (contractsProp.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var contractElem in contractsProp.EnumerateArray())
        {
            if (contractElem.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var contract = ParseContract(contractElem);
            if (contract is not null && !string.IsNullOrWhiteSpace(contract.ContractId))
            {
                _database.SaveContractRecord(contract);
            }
        }
    }

    private static string BuildCriticalErrorCode(string reason)
    {
        return reason switch
        {
            "missing_contract" => "HPS-MISSING-CONTRACT",
            "content_tampered" => "HPS-CONTENT-TAMPERED",
            "content_signature_invalid" => "HPS-CONTENT-SIGNATURE",
            "missing_signature" => "HPS-MISSING-SIGNATURE",
            "invalid_contract" => "HPS-INVALID-CONTRACT",
            _ => "HPS-CRITICAL"
        };
    }

    private static string DescribeCriticalReason(string reason)
    {
        return reason switch
        {
            "missing_contract" => "não existe contrato certificável para esse alvo",
            "content_tampered" => "o conteúdo foi adulterado",
            "content_signature_invalid" => "a assinatura do conteúdo é inválida",
            "missing_signature" => "o conteúdo não tem assinatura ou chave pública",
            "invalid_contract" => "o contrato existe, mas é inválido",
            _ => string.IsNullOrWhiteSpace(reason) ? "erro crítico desconhecido" : reason
        };
    }

    private static bool HasContractAction(JsonElement contractsProp, string actionType)
    {
        if (contractsProp.ValueKind != JsonValueKind.Array || string.IsNullOrWhiteSpace(actionType))
        {
            return false;
        }
        foreach (var contractElem in contractsProp.EnumerateArray())
        {
            if (contractElem.ValueKind != JsonValueKind.Object)
            {
                continue;
            }
            var action = contractElem.TryGetProperty("action_type", out var actionProp) ? actionProp.GetString() ?? string.Empty : string.Empty;
            if (string.Equals(action, actionType, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static SearchResult? ParseSearchResult(JsonElement element)
    {
        try
        {
            var contentHash = element.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() ?? string.Empty : string.Empty;
            var title = element.TryGetProperty("title", out var titleProp) ? titleProp.GetString() ?? string.Empty : string.Empty;
            var description = element.TryGetProperty("description", out var descProp) ? descProp.GetString() ?? string.Empty : string.Empty;
            var mimeType = element.TryGetProperty("mime_type", out var mimeProp) ? mimeProp.GetString() ?? string.Empty : string.Empty;
            var username = element.TryGetProperty("username", out var userProp) ? userProp.GetString() ?? string.Empty : string.Empty;
            var reputation = element.TryGetProperty("reputation", out var repProp) ? repProp.GetInt32() : 100;
            var verified = element.TryGetProperty("verified", out var verProp) && verProp.GetBoolean();
            if (string.IsNullOrWhiteSpace(contentHash))
            {
                return null;
            }
            return new SearchResult(contentHash, title, description, mimeType, username, reputation, verified);
        }
        catch
        {
            return null;
        }
    }

    private void RegisterContractViolation(string targetType, string targetId, string reason)
    {
        if (string.IsNullOrWhiteSpace(targetId))
        {
            return;
        }
        var key = $"{targetType}:{targetId}".ToLowerInvariant();
        _contractViolations.Add(key);
        UpdateContractViolationFlags(reason);
        var label = string.Equals(targetType, "domain", StringComparison.OrdinalIgnoreCase) ? "Domínio" : "Conteúdo";
        StartContractAlert($"{label} com violação contratual: {targetId}");
    }

    private void ClearContractViolation(string targetType, string targetId)
    {
        if (string.IsNullOrWhiteSpace(targetId))
        {
            return;
        }
        var key = $"{targetType}:{targetId}".ToLowerInvariant();
        _contractViolations.Remove(key);
        foreach (var contract in Contracts)
        {
            if (string.Equals(targetType, "domain", StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(contract.Domain, targetId, StringComparison.OrdinalIgnoreCase))
                {
                    contract.ViolationReason = string.Empty;
                    contract.IsContractViolation = false;
                    contract.IntegrityOk = true;
                }
            }
            else
            {
                if (string.Equals(contract.ContentHash, targetId, StringComparison.OrdinalIgnoreCase))
                {
                    contract.ViolationReason = string.Empty;
                    contract.IsContractViolation = false;
                    contract.IntegrityOk = true;
                }
            }
        }
        UpdateContractViolationFlags(string.Empty);
        if (_contractViolations.Count == 0 && PendingTransfersCount == 0)
        {
            StopContractAlert();
        }
    }

    private void DismissCriticalBrowserErrorForTarget(string targetType, string targetId)
    {
        if (!IsCriticalBrowserErrorVisible ||
            string.IsNullOrWhiteSpace(targetType) ||
            string.IsNullOrWhiteSpace(targetId) ||
            !string.Equals(_criticalBrowserTargetType, targetType, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(_criticalBrowserTargetId, targetId, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        IsCriticalBrowserErrorVisible = false;
        CanResolveCriticalBrowserError = false;
        _pendingCriticalContractCertification = null;
        _criticalBrowserTargetType = string.Empty;
        _criticalBrowserTargetId = string.Empty;
        _criticalBrowserReason = string.Empty;
        (ResolveCriticalBrowserErrorCommand as AsyncRelayCommand)?.RaiseCanExecuteChanged();
    }

    private void UpdateContractViolationFlags(string reason)
    {
        foreach (var contract in Contracts)
        {
            var contentKey = $"content:{contract.ContentHash}".ToLowerInvariant();
            var domainKey = $"domain:{contract.Domain}".ToLowerInvariant();
            var isViolation = _contractViolations.Contains(contentKey) ||
                              _contractViolations.Contains(domainKey) ||
                              !string.IsNullOrWhiteSpace(contract.ViolationReason);
            contract.IsContractViolation = isViolation;
            if (isViolation && !string.IsNullOrWhiteSpace(reason))
            {
                contract.ViolationReason = reason;
                contract.IntegrityOk = false;
            }
        }
    }

    private void UpdateContractPendingFlags()
    {
        foreach (var contract in Contracts)
        {
            contract.IsPendingTransfer = _pendingTransfersByContract.ContainsKey(contract.ContractId);
        }
    }

    private void StartContractAlert(string message)
    {
        ContractAlertText = message;
        _contractAlertBlinkOn = false;
        if (_contractAlertTimer is null)
        {
            _contractAlertTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _contractAlertTimer.Tick += (_, _) =>
            {
                _contractAlertBlinkOn = !_contractAlertBlinkOn;
                ContractAlertVisible = _contractAlertBlinkOn;
            };
        }
        ContractAlertVisible = true;
        _contractAlertTimer.Start();
    }

    private void StopContractAlert()
    {
        _contractAlertTimer?.Stop();
        ContractAlertVisible = false;
    }

    private static string TransferFlowPopupId(string transferId, string category)
    {
        var normalizedId = string.IsNullOrWhiteSpace(transferId) ? "unknown" : transferId.Trim();
        var normalizedCategory = string.IsNullOrWhiteSpace(category) ? "transfer" : category.Trim().ToLowerInvariant();
        return $"{normalizedCategory}:{normalizedId}";
    }

    private static string ImportantFlowPopupId(string kind)
    {
        var normalizedKind = string.IsNullOrWhiteSpace(kind) ? "generic" : kind.Trim().ToLowerInvariant();
        return $"important:{normalizedKind}";
    }

    private void StartFlowPopup(string popupId, string title, string status, string details)
    {
        if (string.IsNullOrWhiteSpace(popupId))
        {
            return;
        }

        if (!_flowPopups.TryGetValue(popupId, out var viewModel))
        {
            viewModel = new FlowPopupViewModel(title, status, details, _useUiDispatcher, () => HideFlowPopupWindow(popupId));
            _flowPopups[popupId] = viewModel;
        }
        else
        {
            viewModel.Title = title;
            viewModel.Status = status;
            if (!string.IsNullOrWhiteSpace(details))
            {
                viewModel.Details = details;
            }
            viewModel.ResetCompletion();
        }

        viewModel.AppendLog(status);
    }

    private void UpdateFlowPopupStatus(string popupId, string status)
    {
        if (string.IsNullOrWhiteSpace(status) || !_flowPopups.TryGetValue(popupId, out var viewModel))
        {
            return;
        }
        viewModel.Status = status;
        viewModel.AppendLog(status);
    }

    private void AppendFlowPopupLog(string popupId, string message)
    {
        if (_flowPopups.TryGetValue(popupId, out var viewModel))
        {
            viewModel.AppendLog(message);
        }
    }

    private void MarkFlowPopupDone(string popupId)
    {
        if (_flowPopups.TryGetValue(popupId, out var viewModel))
        {
            viewModel.MarkDone();
        }
    }

    private void OpenFlowPopup(string popupId)
    {
        if (!_flowPopups.TryGetValue(popupId, out var viewModel))
        {
            return;
        }

        if (_useUiDispatcher)
        {
            EnsureFlowPopupWindow(popupId, viewModel);
        }
    }

    private void EnsureFlowPopupWindow(string popupId, FlowPopupViewModel viewModel)
    {
        if (_owner is null || !_useUiDispatcher)
        {
            return;
        }

        if (!_flowPopupWindows.TryGetValue(popupId, out var window) || !window.IsVisible)
        {
            window = new FlowPopupWindow
            {
                DataContext = viewModel
            };
            window.Closed += (_, _) =>
            {
                _flowPopupWindows.Remove(popupId);
            };
            _flowPopupWindows[popupId] = window;
            window.Show(_owner);
            return;
        }

        window.Activate();
    }

    private void HideFlowPopupWindow(string popupId)
    {
        if (_flowPopupWindows.TryGetValue(popupId, out var window))
        {
            window.Close();
        }
        _flowPopupWindows.Remove(popupId);
    }

    private void CloseFlowPopup(string popupId)
    {
        HideFlowPopupWindow(popupId);
        _flowPopups.Remove(popupId);
    }

    private void StartImportantFlow(string title, string status, string details, string kind)
    {
        _importantFlowKind = kind;
        _importantFlowActiveStageIndex = 0;
        ImportantFlowTitle = title;
        ImportantFlowStatus = status;
        if (!string.IsNullOrWhiteSpace(details))
        {
            ImportantFlowDetails = details;
        }
        IsImportantFlowBusy = true;
        StopImportantFlowCompletionBlink();
        if (_useUiDispatcher)
        {
            EnsureImportantFlowWindow();
        }
        ConfigureImportantFlowStages(kind);
        SyncImportantFlowDetailPopup();
        AdvanceImportantFlowStages(kind, status);
        AppendImportantFlowLog(status);
    }

    private void UpdateImportantFlowStatus(string status)
    {
        if (string.IsNullOrWhiteSpace(status))
        {
            return;
        }
        ImportantFlowStatus = status;
        SyncImportantFlowDetailPopup();
        AdvanceImportantFlowStages(_importantFlowKind, status);
        AppendImportantFlowLog(status);
    }

    private void MarkImportantFlowDone()
    {
        IsImportantFlowBusy = false;
        CompleteImportantFlowStages();
        SyncImportantFlowDetailPopup();
        StartImportantFlowCompletionBlink();
    }

    private void ConfigureImportantFlowStages(string kind)
    {
        ImportantFlowStages.Clear();
        foreach (var title in GetImportantFlowStageTitles(kind))
        {
            ImportantFlowStages.Add(new FlowStageItem
            {
                Title = title,
                Detail = "Aguardando início.",
                Marker = "[ ]",
                ActionCommand = new RelayCommand(OpenImportantFlowActionPopup)
            });
        }
        UpdateImportantFlowStageVisuals();
    }

    private static IReadOnlyList<string> GetImportantFlowStageTitles(string kind)
    {
        var normalized = (kind ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "login" => ["Desbloquear credenciais locais", "Conectar ao servidor", "Aguardar autenticação"],
            "message" => ["Preparar operação", "Executar prova ou pagamento", "Enviar para a rede", "Aguardar retorno"],
            "dns" => ["Validar domínio", "Executar prova ou pagamento", "Registrar e confirmar DNS"],
            "content" => ["Solicitar ao servidor", "Buscar na rede", "Validar emissão e contratos", "Abrir conteúdo"],
            "pow" => ["Preparar desafio", "Resolver PoW", "Enviar resposta"],
            "transfer" => ["Preparar operação", "Desbloquear e assinar", "Enviar para a rede", "Aguardar confirmação"],
            "queue" => ["Enviar para fila", "Processamento do servidor"],
            _ => ["Preparar operação", "Processar", "Concluir"]
        };
    }

    private void AdvanceImportantFlowStages(string kind, string status)
    {
        if (ImportantFlowStages.Count == 0)
        {
            return;
        }

        var normalizedStatus = (status ?? string.Empty).Trim().ToLowerInvariant();
        var activeIndex = 0;

        switch ((kind ?? string.Empty).Trim().ToLowerInvariant())
        {
            case "dns":
                if (normalizedStatus.Contains("registrado", StringComparison.Ordinal) || normalizedStatus.Contains("resolvido", StringComparison.Ordinal))
                {
                    CompleteImportantFlowStages();
                    return;
                }
                activeIndex = normalizedStatus.Contains("enviando", StringComparison.Ordinal) ? 2
                    : (normalizedStatus.Contains("pow", StringComparison.Ordinal) || normalizedStatus.Contains("pagamento", StringComparison.Ordinal)) ? 1
                    : 0;
                break;
            case "content":
                if (normalizedStatus.Contains("carregado", StringComparison.Ordinal) || normalizedStatus.Contains("aberto", StringComparison.Ordinal))
                {
                    CompleteImportantFlowStages();
                    return;
                }
                activeIndex = normalizedStatus.Contains("emissão", StringComparison.Ordinal) ||
                              normalizedStatus.Contains("contrato", StringComparison.Ordinal) ||
                              normalizedStatus.Contains("valid", StringComparison.Ordinal) ? 2
                    : normalizedStatus.Contains("buscando", StringComparison.Ordinal) ||
                      normalizedStatus.Contains("usuários", StringComparison.Ordinal) ||
                      normalizedStatus.Contains("usuarios", StringComparison.Ordinal) ||
                      normalizedStatus.Contains("servidores conhecidos", StringComparison.Ordinal) ? 1 : 0;
                break;
            case "login":
                if (normalizedStatus.Contains("autentic", StringComparison.Ordinal))
                {
                    activeIndex = 2;
                }
                else if (normalizedStatus.Contains("conect", StringComparison.Ordinal))
                {
                    activeIndex = 1;
                }
                else
                {
                    activeIndex = 0;
                }
                break;
            case "pow":
                if (normalizedStatus.Contains("conclu", StringComparison.Ordinal))
                {
                    CompleteImportantFlowStages();
                    return;
                }
                activeIndex = normalizedStatus.Contains("envi", StringComparison.Ordinal) ? 2
                    : normalizedStatus.Contains("resolv", StringComparison.Ordinal) ? 1
                    : 0;
                break;
            case "transfer":
                if (normalizedStatus.Contains("conclu", StringComparison.Ordinal))
                {
                    CompleteImportantFlowStages();
                    return;
                }
                activeIndex = normalizedStatus.Contains("status:", StringComparison.Ordinal) || normalizedStatus.Contains("aguard", StringComparison.Ordinal) || normalizedStatus.Contains("minerador", StringComparison.Ordinal) ? 3
                    : normalizedStatus.Contains("envi", StringComparison.Ordinal) || normalizedStatus.Contains("fila", StringComparison.Ordinal) ? 2
                    : normalizedStatus.Contains("assin", StringComparison.Ordinal) || normalizedStatus.Contains("descriptograf", StringComparison.Ordinal) ? 1
                    : 0;
                break;
            case "message":
                if (normalizedStatus.Contains("aprovad", StringComparison.Ordinal) ||
                    normalizedStatus.Contains("rejeitad", StringComparison.Ordinal) ||
                    normalizedStatus.Contains("enviada", StringComparison.Ordinal) ||
                    normalizedStatus.Contains("enviado", StringComparison.Ordinal) ||
                    normalizedStatus.Contains("ja esta liberada", StringComparison.Ordinal) ||
                    normalizedStatus.Contains("falha", StringComparison.Ordinal))
                {
                    CompleteImportantFlowStages();
                    return;
                }
                activeIndex = normalizedStatus.Contains("estado das mensagens", StringComparison.Ordinal) ||
                              normalizedStatus.Contains("aguard", StringComparison.Ordinal) ? 3
                    : normalizedStatus.Contains("solicitando", StringComparison.Ordinal) ||
                      normalizedStatus.Contains("enviando", StringComparison.Ordinal) ? 2
                    : normalizedStatus.Contains("pow", StringComparison.Ordinal) ||
                      normalizedStatus.Contains("pagamento", StringComparison.Ordinal) ||
                      normalizedStatus.Contains("custo atual", StringComparison.Ordinal) ? 1
                    : 0;
                break;
            case "queue":
                if (normalizedStatus.Contains("conclu", StringComparison.Ordinal))
                {
                    CompleteImportantFlowStages();
                    return;
                }
                activeIndex = normalizedStatus.Contains("process", StringComparison.Ordinal) ? 1 : 0;
                break;
            default:
                if (normalizedStatus.Contains("conclu", StringComparison.Ordinal))
                {
                    CompleteImportantFlowStages();
                    return;
                }
                activeIndex = normalizedStatus.Contains("envi", StringComparison.Ordinal) ? Math.Min(2, ImportantFlowStages.Count - 1)
                    : normalizedStatus.Contains("process", StringComparison.Ordinal) ? Math.Min(1, ImportantFlowStages.Count - 1)
                    : 0;
                break;
        }

        for (var index = 0; index < ImportantFlowStages.Count; index++)
        {
            var stage = ImportantFlowStages[index];
            if (index < activeIndex)
            {
                stage.Marker = "[OK]";
                stage.IsCompleted = true;
                stage.IsActive = false;
                stage.IsDimmed = false;
                stage.IsPendingUserAction = false;
                stage.PendingLabel = string.Empty;
            }
            else if (index == activeIndex)
            {
                stage.Marker = "[..]";
                stage.IsCompleted = false;
                stage.IsActive = true;
                stage.IsDimmed = false;
                stage.IsPendingUserAction = RequiresUserAction(kind, status);
                stage.PendingLabel = stage.IsPendingUserAction ? "PENDENTE: clique para resolver" : "Processando...";
                stage.Detail = status;
            }
            else
            {
                stage.Marker = "[ ]";
                stage.IsCompleted = false;
                stage.IsActive = false;
                stage.IsDimmed = true;
                stage.IsPendingUserAction = false;
                stage.PendingLabel = string.Empty;
            }
        }

        _importantFlowActiveStageIndex = activeIndex;

        UpdateImportantFlowStageVisuals();
    }

    private void CompleteImportantFlowStages()
    {
        foreach (var stage in ImportantFlowStages)
        {
            stage.Marker = "[OK]";
            stage.IsCompleted = true;
            stage.IsActive = false;
            stage.IsDimmed = false;
            stage.IsPendingUserAction = false;
            stage.PendingLabel = string.Empty;
            if (string.IsNullOrWhiteSpace(stage.Detail) || string.Equals(stage.Detail, "Aguardando início.", StringComparison.Ordinal))
            {
                stage.Detail = "Etapa concluída.";
            }
        }
        StopImportantFlowStageBlink();
        UpdateImportantFlowStageVisuals();
    }

    private static bool RequiresUserAction(string kind, string status)
    {
        var normalizedKind = (kind ?? string.Empty).Trim().ToLowerInvariant();
        var normalizedStatus = (status ?? string.Empty).Trim().ToLowerInvariant();
        if (normalizedKind == "transfer" && normalizedStatus.Contains("assin", StringComparison.Ordinal))
        {
            return true;
        }
        return normalizedStatus.Contains("clique", StringComparison.Ordinal) ||
               normalizedStatus.Contains("confirm", StringComparison.Ordinal) ||
               normalizedStatus.Contains("senha", StringComparison.Ordinal);
    }

    private void UpdateImportantFlowStageVisuals()
    {
        var hasPending = false;
        foreach (var stage in ImportantFlowStages)
        {
            stage.Opacity = stage.IsDimmed ? 0.38 : 1.0;
            stage.BlinkVisible = stage.IsPendingUserAction && stage.IsActive;
            hasPending |= stage.IsPendingUserAction && stage.IsActive;
        }

        if (hasPending)
        {
            StartImportantFlowStageBlink();
        }
        else
        {
            StopImportantFlowStageBlink();
        }
    }

    private void StartImportantFlowStageBlink()
    {
        if (!_useUiDispatcher)
        {
            return;
        }

        _importantFlowStageBlinkTimer ??= new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(650)
        };
        _importantFlowStageBlinkTimer.Tick -= OnImportantFlowStageBlink;
        _importantFlowStageBlinkTimer.Tick += OnImportantFlowStageBlink;
        _importantFlowStageBlinkTimer.Start();
    }

    private void StopImportantFlowStageBlink()
    {
        _importantFlowStageBlinkTimer?.Stop();
        foreach (var stage in ImportantFlowStages)
        {
            stage.BlinkVisible = true;
        }
    }

    private void OnImportantFlowStageBlink(object? sender, EventArgs e)
    {
        foreach (var stage in ImportantFlowStages.Where(item => item.IsPendingUserAction && item.IsActive))
        {
            stage.BlinkVisible = !stage.BlinkVisible;
        }
    }

    private void SyncImportantFlowDetailPopup()
    {
        var popupId = ImportantFlowPopupId(_importantFlowKind);
        if (!_flowPopups.TryGetValue(popupId, out var viewModel))
        {
            viewModel = new FlowPopupViewModel(
                string.IsNullOrWhiteSpace(ImportantFlowTitle) ? "Processo" : ImportantFlowTitle,
                string.IsNullOrWhiteSpace(ImportantFlowStatus) ? "Em andamento" : ImportantFlowStatus,
                string.IsNullOrWhiteSpace(ImportantFlowDetails) ? $"Etapa ativa: {_importantFlowActiveStageIndex + 1}" : ImportantFlowDetails,
                _useUiDispatcher,
                () => HideFlowPopupWindow(popupId));
            _flowPopups[popupId] = viewModel;
        }
        else
        {
            viewModel.Title = string.IsNullOrWhiteSpace(ImportantFlowTitle) ? "Processo" : ImportantFlowTitle;
            viewModel.Status = string.IsNullOrWhiteSpace(ImportantFlowStatus) ? "Em andamento" : ImportantFlowStatus;
            viewModel.Details = string.IsNullOrWhiteSpace(ImportantFlowDetails) ? $"Etapa ativa: {_importantFlowActiveStageIndex + 1}" : ImportantFlowDetails;
            if (IsImportantFlowBusy)
            {
                viewModel.ResetCompletion();
            }
        }

        viewModel.Log = ImportantFlowLog;
        viewModel.IsBusy = IsImportantFlowBusy;
        if (!IsImportantFlowBusy)
        {
            viewModel.IsCompleted = true;
        }
    }

    private void OpenImportantFlowActionPopup()
    {
        if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
        {
            var transferId = _pendingExchangeTransferId ?? _pendingTransferId ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(transferId))
            {
                var monitorPopupId = TransferFlowPopupId(transferId, "monitor");
                if (_flowPopups.ContainsKey(monitorPopupId))
                {
                    OpenFlowPopup(monitorPopupId);
                    return;
                }
            }
        }

        OpenFlowPopup(ImportantFlowPopupId(_importantFlowKind));
    }

    private void StartImportantFlowCompletionBlink()
    {
        if (!_useUiDispatcher)
        {
            IsImportantFlowCompleted = true;
            ImportantFlowCompletedVisible = true;
            return;
        }
        IsImportantFlowCompleted = true;
        if (_importantFlowCompletedTimer is null)
        {
            _importantFlowCompletedTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(0.8)
            };
            _importantFlowCompletedTimer.Tick += (_, _) =>
            {
                ImportantFlowCompletedVisible = !ImportantFlowCompletedVisible;
            };
        }
        ImportantFlowCompletedVisible = true;
        _importantFlowCompletedTimer.Start();
    }

    private void StopImportantFlowCompletionBlink()
    {
        IsImportantFlowCompleted = false;
        ImportantFlowCompletedVisible = false;
        _importantFlowCompletedTimer?.Stop();
    }

    private void TryFinalizePendingExchangeFromWallet(HashSet<string> syncedVoucherIds)
    {
        if (syncedVoucherIds.Count == 0 || string.IsNullOrWhiteSpace(_pendingExchangeVoucherId))
        {
            return;
        }
        if (!syncedVoucherIds.Contains(_pendingExchangeVoucherId))
        {
            return;
        }

        ExchangeStatus = "Câmbio concluído.";
        TransferStatus = "Transferência concluída (carteira sincronizada).";
        if (!string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
        {
            var details = string.IsNullOrWhiteSpace(_pendingExchangeTransferId)
                ? "Transferência finalizada."
                : $"Transferência: {_pendingExchangeTransferId}";
            StartImportantFlow("Transferência em andamento", "Status: Transferência concluída", details, "transfer");
        }
        else
        {
            UpdateImportantFlowStatus("Status: Transferência concluída");
        }
        if (!string.IsNullOrWhiteSpace(_pendingExchangeTransferId))
        {
            AppendImportantFlowLog($"Transferência {_pendingExchangeTransferId}: concluída após sincronização da carteira.");
            _completedTransferIds.Add(_pendingExchangeTransferId);
            _transferStatusCache[_pendingExchangeTransferId] = "completed";
        }
        GhostPendingExchangeSourceVouchers();
        ResetExchangePendingRefreshState();
        MarkImportantFlowDone();
        _pendingExchangeTransferId = null;
        _pendingExchangeVoucherId = null;
        _pendingExchangeQuoteId = null;
        UpdateAutomaticStateSyncLoop();
        RaiseCommandCanExecuteChanged();
    }

    private void HandleExchangePendingState(string transferId, string newVoucherId)
    {
        transferId = string.IsNullOrWhiteSpace(transferId) ? (_pendingExchangeTransferId ?? string.Empty) : transferId;
        newVoucherId = string.IsNullOrWhiteSpace(newVoucherId) ? (_pendingExchangeVoucherId ?? string.Empty) : newVoucherId;
        var transferStatus = string.IsNullOrWhiteSpace(transferId) ? string.Empty : (_transferStatusCache.TryGetValue(transferId, out var cachedStatus) ? cachedStatus : string.Empty);
        var transferMiner = string.IsNullOrWhiteSpace(transferId) ? string.Empty : (_transferMinerCache.TryGetValue(transferId, out var cachedMiner) ? cachedMiner : string.Empty);
        var hasMiner = !string.IsNullOrWhiteSpace(transferMiner);
        var statusNormalized = transferStatus?.Trim().ToLowerInvariant() ?? string.Empty;
        if (IsTransferFinalStatus(statusNormalized))
        {
            FinalizeExchangePendingState(transferId, transferStatus, newVoucherId);
            return;
        }
        if (hasMiner && (string.IsNullOrWhiteSpace(statusNormalized) || statusNormalized == "awaiting_selector"))
        {
            // Defensive UI mapping: if a miner is already assigned, do not keep
            // showing "awaiting_selector" due to stale/out-of-order events.
            transferStatus = "pending_signature";
            if (!string.IsNullOrWhiteSpace(transferId))
            {
                _transferStatusCache[transferId] = transferStatus;
            }
        }
        var statusLabel = string.IsNullOrWhiteSpace(transferStatus)
            ? "Aguardando seleção de minerador"
            : DescribeTransferStatus(transferStatus, string.Empty);
        if (string.IsNullOrWhiteSpace(transferStatus) && hasMiner)
        {
            statusLabel = "Minerador atribuído";
        }
        ExchangeStatus = hasMiner
            ? $"Câmbio iniciado. Minerador atribuído: {transferMiner}. Aguardando assinatura do minerador."
            : "Câmbio iniciado. Aguardando seleção de minerador e validação do relatório do minerador.";
        TransferStatus = statusLabel;
        if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
        {
            UpdateImportantFlowStatus(ExchangeStatus);
        }
        _pendingExchangeTransferId = string.IsNullOrWhiteSpace(transferId) ? null : transferId;
        _pendingExchangeVoucherId = string.IsNullOrWhiteSpace(newVoucherId) ? null : newVoucherId;
        var detailsText = string.IsNullOrWhiteSpace(transferId)
            ? "Aguardando seletor/minerador."
            : $"Transferência: {transferId}";
        if (!string.IsNullOrWhiteSpace(transferMiner))
        {
            detailsText += $"\nMinerador: {transferMiner}";
        }
        var popupId = TransferFlowPopupId(transferId, "monitor");
        StartFlowPopup(popupId, "Transferência em andamento", $"Status: {statusLabel}", detailsText);
        if (!string.IsNullOrWhiteSpace(transferId))
        {
            AppendFlowPopupLog(popupId, $"Transferência {transferId}: câmbio iniciado, status {statusLabel.ToLowerInvariant()}.");
        }
        else
        {
            AppendFlowPopupLog(popupId, $"Câmbio iniciado, status {statusLabel.ToLowerInvariant()}.");
        }
        ScheduleExchangePendingRefresh(transferId, newVoucherId, transferStatus, transferMiner);
        _pendingExchangeQuoteId = null;
        UpdateAutomaticStateSyncLoop();
        RaiseCommandCanExecuteChanged();
    }

    private async Task HandleVoucherOfferAsync(JsonElement payload)
    {
        if (_privateKey is null)
        {
            return;
        }

        if (!payload.TryGetProperty("voucher_id", out var idProp) ||
            !payload.TryGetProperty("payload", out var payloadProp))
        {
            return;
        }

        var voucherId = idProp.GetString();
        if (string.IsNullOrWhiteSpace(voucherId))
        {
            return;
        }

        lock (_voucherConfirmationLock)
        {
            if (_voucherConfirmationsCompleted.Contains(voucherId))
            {
                return;
            }
            if (!_voucherConfirmationsInFlight.Add(voucherId))
            {
                return;
            }
        }

        try
        {
            var payloadJson = payload.TryGetProperty("payload_canonical", out var payloadCanonicalProp) &&
                              payloadCanonicalProp.ValueKind == JsonValueKind.String
                ? payloadCanonicalProp.GetString() ?? string.Empty
                : BrowserDatabase.CanonicalizePayload(payloadProp);
            if (string.IsNullOrWhiteSpace(payloadJson))
            {
                payloadJson = BrowserDatabase.CanonicalizePayload(payloadProp);
            }
            var signature = CryptoUtils.SignPayload(_privateKey, payloadJson);

            HpsMintStatus = "Voucher recebido. Confirmando...";
            HpsMiningStatus = "Voucher emitido";
            AppendPowLog("Voucher HPS recebido. Confirmando assinatura.");
            await _socketClient.EmitAsync("confirm_hps_voucher", new
            {
                voucher_id = voucherId,
                owner_signature = Convert.ToBase64String(signature),
                payload_signed_text = payloadJson
            });
            lock (_voucherConfirmationLock)
            {
                _voucherConfirmationsCompleted.Add(voucherId);
            }
            ScheduleNextContinuousMining();
        }
        finally
        {
            lock (_voucherConfirmationLock)
            {
                _voucherConfirmationsInFlight.Remove(voucherId);
            }
        }
    }

    private void FinalizeExchangePendingState(string transferId, string transferStatus, string newVoucherId)
    {
        var normalizedStatus = transferStatus?.Trim().ToLowerInvariant() ?? string.Empty;
        var label = DescribeTransferStatus(transferStatus, string.Empty);
        ExchangeStatus = string.IsNullOrWhiteSpace(label) ? "Câmbio concluído." : $"Câmbio: {label}.";
        TransferStatus = string.IsNullOrWhiteSpace(label) ? "Transferência concluída." : label;
        if (!string.IsNullOrWhiteSpace(transferId))
        {
            if (normalizedStatus is "signed" or "completed")
            {
                _completedTransferIds.Add(transferId);
            }
            _transferStatusCache[transferId] = transferStatus;
        }

        var popupId = TransferFlowPopupId(transferId, "monitor");
        var details = string.IsNullOrWhiteSpace(transferId) ? "Transferência finalizada." : $"Transferência: {transferId}";
        StartFlowPopup(popupId, "Transferência em andamento", $"Status: {label}", details);
        MarkFlowPopupDone(popupId);
        if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
        {
            UpdateImportantFlowStatus("Status: Transferência concluída");
            MarkImportantFlowDone();
        }

        ResetExchangePendingRefreshState();
        _pendingExchangeTransferId = null;
        _pendingExchangeVoucherId = string.IsNullOrWhiteSpace(newVoucherId) ? null : newVoucherId;
        _pendingExchangeQuoteId = null;
        if (normalizedStatus is "signed" or "completed" or "finalized")
        {
            GhostPendingExchangeSourceVouchers();
        }
        if (!string.IsNullOrWhiteSpace(_pendingExchangeVoucherId) && _socketClient.IsConnected)
        {
            QueueAutomaticWalletRefresh();
        }
        UpdateAutomaticStateSyncLoop();
        RaiseCommandCanExecuteChanged();
    }

    private void ScheduleExchangePendingRefresh(string transferId, string newVoucherId, string transferStatus, string transferMiner)
    {
        _ = transferId;
        _ = newVoucherId;
        _ = transferStatus;
        _ = transferMiner;
        UpdateAutomaticStateSyncLoop();
    }

    private void ResetExchangePendingRefreshState()
    {
        _exchangePendingRefreshCts?.Cancel();
        _exchangePendingRefreshCts?.Dispose();
        _exchangePendingRefreshCts = null;
        _lastExchangePendingRefreshSnapshot = string.Empty;
        _lastExchangePendingRefreshAt = DateTimeOffset.MinValue;
    }

    private (string Status, string Miner) MergeTransferSnapshot(string transferId, string incomingStatus, string incomingMiner)
    {
        var existingStatus = string.IsNullOrWhiteSpace(transferId) ? string.Empty : (_transferStatusCache.TryGetValue(transferId, out var cachedStatus) ? cachedStatus : string.Empty);
        var existingMiner = string.IsNullOrWhiteSpace(transferId) ? string.Empty : (_transferMinerCache.TryGetValue(transferId, out var cachedMiner) ? cachedMiner : string.Empty);
        var mergedMiner = string.IsNullOrWhiteSpace(incomingMiner) ? existingMiner : incomingMiner;
        var mergedStatus = ChoosePreferredTransferStatus(existingStatus, incomingStatus, mergedMiner);
        if (!string.IsNullOrWhiteSpace(transferId))
        {
            _transferStatusCache[transferId] = mergedStatus;
            _transferMinerCache[transferId] = mergedMiner;
        }
        return (mergedStatus, mergedMiner);
    }

    private static string ChoosePreferredTransferStatus(string currentStatus, string incomingStatus, string mergedMiner)
    {
        var current = currentStatus?.Trim() ?? string.Empty;
        var incoming = incomingStatus?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(current))
        {
            current = incoming;
        }
        if (string.IsNullOrWhiteSpace(incoming))
        {
            incoming = current;
        }
        var currentNormalized = current.ToLowerInvariant();
        var incomingNormalized = incoming.ToLowerInvariant();
        if (IsTransferFinalStatus(currentNormalized))
        {
            return current;
        }
        if (IsTransferFinalStatus(incomingNormalized))
        {
            return incoming;
        }
        if (!string.IsNullOrWhiteSpace(mergedMiner))
        {
            if (incomingNormalized == "awaiting_selector")
            {
                if (currentNormalized == "pending_signature")
                {
                    return current;
                }
                return "pending_signature";
            }
            if (incomingNormalized == "pending_signature")
            {
                return incoming;
            }
        }
        return string.IsNullOrWhiteSpace(incoming) ? current : incoming;
    }

    private static bool IsTransferFinalStatus(string status)
    {
        return status is "signed" or "completed" or "invalidated" or "rejected" or "renounced" or "cancelled" or "expired";
    }

    private static string DescribeTransferStatus(string status, string reason)
    {
        var trimmed = status?.Trim().ToLowerInvariant() ?? string.Empty;
        return trimmed switch
        {
            "awaiting_selector" => "Aguardando seletor",
            "pending_signature" => "Aguardando assinatura do minerador",
            "signature_submitted" => "Assinatura recebida pelo servidor",
            "assigned" => string.IsNullOrWhiteSpace(reason) ? "Minerador atribuído" : $"Minerador atribuído ({reason})",
            "signed" => "Assinatura concluída",
            "completed" => "Transferência concluída",
            "invalidated" => string.IsNullOrWhiteSpace(reason) ? "Transferência invalidada" : $"Transferência invalidada ({reason})",
            "rejected" => "Transferência rejeitada",
            "renounced" => "Transferência renunciada",
            "cancelled" => "Transferência cancelada",
            "expired" => "Transferência expirada",
            _ => string.IsNullOrWhiteSpace(reason) ? status : $"{status} ({reason})"
        };
    }

    private void AppendImportantFlowLog(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return;
        }
        var line = $"[{DateTime.Now:HH:mm:ss}] {message}";
        if (string.IsNullOrWhiteSpace(ImportantFlowLog))
        {
            ImportantFlowLog = line;
        }
        else
        {
            ImportantFlowLog = ImportantFlowLog + "\n" + line;
        }
        var maxLen = 4000;
        if (ImportantFlowLog.Length > maxLen)
        {
            ImportantFlowLog = ImportantFlowLog[^maxLen..];
        }
        if (_flowPopups.TryGetValue(ImportantFlowPopupId(_importantFlowKind), out var viewModel))
        {
            viewModel.Log = ImportantFlowLog;
        }
    }

    private void EnsureImportantFlowWindow()
    {
        if (_owner is null || !_useUiDispatcher)
        {
            return;
        }
        if (_importantFlowWindow is null || !_importantFlowWindow.IsVisible)
        {
            _importantFlowWindow = new ImportantFlowWindow();
            _importantFlowWindow.DataContext = this;
            _importantFlowWindow.Closed += (_, _) =>
            {
                _importantFlowWindow = null;
                _importantFlowKind = string.Empty;
            };
            _importantFlowWindow.Show(_owner);
        }
        else
        {
            _importantFlowWindow.Activate();
        }
    }

    private void CloseImportantFlowWindow()
    {
        if (_importantFlowWindow is null)
        {
            return;
        }
        StopImportantFlowStageBlink();
        _importantFlowWindow.Close();
        _importantFlowWindow = null;
        _importantFlowKind = string.Empty;
        IsImportantFlowBusy = false;
        StopImportantFlowCompletionBlink();
    }

    private void BuildTourSteps()
    {
        _tourSteps.Clear();
        if (_isMinerMode)
        {
            _tourSteps.Add(new TourStep(
                "Bem-vinda ao HPS Miner",
                "Este tour apresenta o fluxo de conexão, autenticação e mineração do HPS Miner."
            ));
            _tourSteps.Add(new TourStep(
                "1) Configurar acesso",
                "Informe servidor, usuário e senha da chave local para autenticar com assinatura criptográfica."
            ));
            _tourSteps.Add(new TourStep(
                "2) Entrar na rede",
                "Conecte-se e aguarde a autenticação. Se houver PoW, o progresso aparecerá em tempo real."
            ));
            _tourSteps.Add(new TourStep(
                "3) Operação de mineração",
                "Use mineração contínua, assinatura automática e pagamento automático de multa conforme sua estratégia."
            ));
            _tourSteps.Add(new TourStep(
                "4) Ajustes de desempenho",
                "No Config, ajuste as threads de PoW para equilibrar velocidade, CPU e consumo."
            ));
            return;
        }

        _tourSteps.Add(new TourStep(
            "Primeiros passos no HPS Browser",
            "Este tour mostra como entrar na rede P2P e começar a navegar com segurança."
        ));
        _tourSteps.Add(new TourStep(
            "1) Escolha o servidor",
            "Na aba Login, selecione um servidor confiável ou digite o endereço (ex: host:porta)."
        ));
        _tourSteps.Add(new TourStep(
            "2) Adicione servidores",
            "Na aba Servidores, adicione novos servidores e conecte no que preferir."
        ));
        _tourSteps.Add(new TourStep(
            "3) Preencha usuário e senha da chave",
            "Use seu usuário e a senha local da chave (.hps.key). O login no servidor usa assinatura criptográfica."
        ));
        _tourSteps.Add(new TourStep(
            "4) SSL/TLS e reconexão",
            "Ative SSL/TLS se o servidor usar HTTPS/TLS. A reconexão automática ajuda quando a rede cai."
        ));
        _tourSteps.Add(new TourStep(
            "5) Entrar na rede",
            "Clique em 'Entrar na Rede'. Caso haja PoW, o monitor exibirá o progresso."
        ));
        _tourSteps.Add(new TourStep(
            "6) Navegar e buscar",
            "Na aba Navegador, use hps://<hash> ou hps://dns:<dominio>. Use Buscar para localizar conteúdo."
        ));
        _tourSteps.Add(new TourStep(
            "7) DNS e uploads",
            "No DNS, registre domínio apontando para o hash do conteúdo. Para enviar conteúdo, use a aba Upload."
        ));
        _tourSteps.Add(new TourStep(
            "8) Certificados e pHPS",
            "Na área de certificados, acompanhe contratos, pendências, vouchers, gastos e os títulos pHPS da custódia."
        ));
        _tourSteps.Add(new TourStep(
            "9) Configurações importantes",
            "Em Config: ajuste threads do PoW, assinatura automática e seleção randômica de minerador."
        ));
    }

    private void UpdateTourStep()
    {
        if (_tourSteps.Count == 0)
        {
            TourTitle = string.Empty;
            TourBody = string.Empty;
            TourStepLabel = string.Empty;
            return;
        }
        if (_tourIndex < 0)
        {
            _tourIndex = 0;
        }
        if (_tourIndex >= _tourSteps.Count)
        {
            _tourIndex = _tourSteps.Count - 1;
        }
        var step = _tourSteps[_tourIndex];
        TourTitle = step.Title;
        TourBody = step.Body;
        TourStepLabel = $"Passo {_tourIndex + 1} de {_tourSteps.Count}";
        (NextTourCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (PrevTourCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    private void StartTour()
    {
        if (_owner is null)
        {
            return;
        }
        EnsureTourWindow();
        UpdateTourStep();
    }

    public async Task ShowHelpAsync(string topic)
    {
        if (_owner is null)
        {
            return;
        }

        var normalized = (topic ?? string.Empty).Trim().ToLowerInvariant();
        var (title, body) = normalized switch
        {
            "login" => (
                "Ajuda: Login",
                "Escolha o servidor, informe seu usuário e a senha local da chave.\n\n" +
                "Servidor: endereço do nó ao qual você vai se conectar.\n" +
                "Usuário: identidade usada nas assinaturas e operações.\n" +
                "Senha da chave: desbloqueia sua chave privada local.\n" +
                "Login automático e reconexão automática facilitam o uso contínuo.\n" +
                "Usar SSL/TLS deve ser marcado quando o servidor operar com HTTPS/TLS."
            ),
            "browser" => (
                "Ajuda: Navegador",
                "Use `hps://hash` para abrir conteúdo por hash e `hps://dns:dominio` para abrir via DNS.\n\n" +
                "Voltar, Avançar e Recarregar funcionam como em um navegador comum.\n" +
                "Segurança mostra a situação criptográfica e contratual do conteúdo.\n" +
                "Buscar abre a pesquisa da rede.\n" +
                "Salvar grava localmente o conteúdo que está aberto."
            ),
            "dns" => (
                "Ajuda: DNS",
                "Esta página serve para registrar e resolver domínios descentralizados.\n\n" +
                "Domínio: nome que será publicado.\n" +
                "Hash do conteúdo: conteúdo para o qual o domínio vai apontar.\n" +
                "Registrar publica ou atualiza o vínculo.\n" +
                "Resolver consulta o conteúdo atual do domínio.\n" +
                "Segurança mostra quem emitiu e validou o registro."
            ),
            "upload" => (
                "Ajuda: Upload",
                "Selecione um arquivo e preencha título, descrição e MIME.\n\n" +
                "Ao enviar, o navegador calcula o hash, assina o conteúdo e pede PoW ou pagamento HPS quando necessário.\n" +
                "Depois da confirmação do servidor, o hash publicado aparece no campo final e pode ser usado em navegação, DNS e contratos."
            ),
            "wallet" => (
                "Ajuda: Carteira HPS",
                "Aqui você acompanha seu saldo e os vouchers emitidos para sua conta.\n\n" +
                "Minerar HPS inicia um fluxo de PoW para obtenção de HPS.\n" +
                "A seção de mineração contínua mostra hashrate, tentativas, tempo e pendências operacionais.\n" +
                "Também é aqui que você vê e paga multas relacionadas à atividade de minerador."
            ),
            "dkvhps" => (
                "Ajuda: DKVHPS",
                "DKVHPS significa Descriptografy Key for Vouchers of HPS.\n\n" +
                "É a camada de descriptografia de vouchers usada no espelhamento local e na auditoria assistida de linhagens.\n" +
                "Cada voucher possui uma chave individual e uma chave de linhagem.\n" +
                "O arquivo local do voucher é protegido em três camadas: chave do voucher, chave da linhagem e chave local do navegador.\n" +
                "Nesta aba você vê as linhagens disponíveis, o voucher potencialmente ativo, os hashes declarados, as chaves descriptografadas localmente, o resultado da verificação de integridade e pode abrir um inspetor detalhado.\n" +
                "A validade continua dependendo de assinatura, encadeamento e contratos da custódia emissora; o DKVHPS não substitui essa validação."
            ),
            "actions" => (
                "Ajuda: Ações HPS",
                "Esta página concentra operações que movimentam propriedade ou valor.\n\n" +
                "Escolha o tipo de ação e preencha apenas os campos exigidos por aquela operação.\n" +
                "Você pode transferir arquivo, HPS, domínio e API App.\n" +
                "Ao aplicar a ação, o navegador prepara o contrato correspondente e executa PoW ou pagamento quando necessário."
            ),
            "exchange" => (
                "Ajuda: Câmbio",
                "A aba Câmbio mostra emissores e condições econômicas para conversão.\n\n" +
                "Primeiro escolha um emissor.\n" +
                "Depois solicite a cotação.\n" +
                "Se a cotação estiver adequada, confirme a conversão.\n" +
                "As tabelas exibem quantidade emitida, multiplicador e taxa observada em cada servidor."
            ),
            "network" => (
                "Ajuda: Rede",
                "Esta página mostra os nós conhecidos da rede.\n\n" +
                "Atualizar pede um retrato novo ao servidor.\n" +
                "Sincronizar força atualização dos dados conhecidos.\n" +
                "Meu Nó destaca suas próprias informações.\n" +
                "Ao selecionar um nó, o painel lateral mostra usuário, endereço, tipo, ID e estado atual."
            ),
            "contracts" => (
                "Ajuda: Certificados",
                "Use esta área para inspecionar documentos e fluxos auditáveis da rede.\n\n" +
                "Pendências mostra ações aguardando decisão.\n" +
                "Vouchers ajuda a rastrear origem e uso de HPS.\n" +
                "Contratos permite buscar, abrir e agir sobre contratos específicos.\n" +
                "Gastos mostra a análise de consumo de vouchers.\n" +
                "Quando aplicável, também é aqui que você solicita nova checagem de emissão."
            ),
            "phps" => (
                "Ajuda: pHPS",
                "pHPS é um título de dívida da custódia.\n\n" +
                "A grade principal mostra contratos abertos e o retorno prometido.\n" +
                "Reservado indica quanto do pagamento futuro já foi separado para aquela dívida.\n" +
                "Minhas posições mostra os títulos que você assumiu e o ganho esperado em cada um.\n" +
                "Cada dívida é individual, sem financiamento coletivo."
            ),
            "config" => (
                "Ajuda: Configurações",
                "Esta página reúne ajustes locais do navegador.\n\n" +
                "Você pode gerar, exportar e importar chaves.\n" +
                "Também ajusta threads de PoW e automações como assinatura automática e aceite automático de seleção de minerador.\n" +
                "A seção de ajuda permite controlar o tour inicial."
            ),
            "servers" => (
                "Ajuda: Servidores",
                "Aqui você mantém a lista de servidores conhecidos.\n\n" +
                "Adicionar inclui um novo endereço na lista.\n" +
                "Remover apaga o servidor selecionado da lista local.\n" +
                "Conectar usa o servidor selecionado como alvo atual.\n" +
                "Atualizar consulta novamente status e reputação."
            ),
            "stats" => (
                "Ajuda: Estatísticas",
                "Esta página mostra métricas locais da sua sessão.\n\n" +
                "Você acompanha tempo conectado, dados enviados e recebidos, quantidade de conteúdos baixados e publicados, registros DNS e atividade de PoW."
            ),
            _ => (
                "Ajuda",
                "Esta janela explica o objetivo da página atual e como usar os controles principais."
            )
        };

        await _promptService.AlertAsync(_owner, title, body);
    }

    private void ShowTourIfNeeded()
    {
        if (!ShowTourOnStartup || _owner is null)
        {
            return;
        }
        RunOnUi(() =>
        {
            EnsureTourWindow();
            UpdateTourStep();
        });
    }

    private void EnsureTourWindow()
    {
        if (_owner is null)
        {
            return;
        }
        if (_tourWindow is null || !_tourWindow.IsVisible)
        {
            _tourWindow = new TourWindow();
            _tourWindow.DataContext = this;
            _tourWindow.Closed += (_, _) => { _tourWindow = null; };
            _tourWindow.Show(_owner);
        }
        else
        {
            _tourWindow.Activate();
        }
    }

    private void AdvanceTour()
    {
        if (_tourIndex < _tourSteps.Count - 1)
        {
            _tourIndex++;
            UpdateTourStep();
        }
    }

    private void BackTour()
    {
        if (_tourIndex > 0)
        {
            _tourIndex--;
            UpdateTourStep();
        }
    }

    private void CloseTour()
    {
        if (_tourWindow is null)
        {
            return;
        }
        _tourWindow.Close();
        _tourWindow = null;
    }

    private void AppendPowLog(string message)
    {
        var line = $"[{DateTime.Now:HH:mm:ss}] {message}";
        if (string.IsNullOrWhiteSpace(PowLogText))
        {
            PowLogText = line;
        }
        else
        {
            PowLogText = PowLogText + "\n" + line;
        }

        var maxLen = 4000;
        if (PowLogText.Length > maxLen)
        {
            PowLogText = PowLogText[^maxLen..];
        }
    }

    private void InitializeSessionStats()
    {
        ResetSessionStats();
    }

    private void StartSessionTimer()
    {
        if (_sessionTimer is not null)
        {
            return;
        }
        _sessionTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _sessionTimer.Tick += (_, _) => UpdateSessionElapsed();
        _sessionTimer.Start();
    }

    private void ResetSessionStats()
    {
        _sessionStartedAt = DateTimeOffset.UtcNow;
        _sessionBytesSent = 0;
        _sessionBytesReceived = 0;
        _contentDownloadedCount = 0;
        _contentPublishedCount = 0;
        _dnsRegisteredCount = 0;
        _downloadedContentHashes.Clear();
        _publishedContentHashes.Clear();
        _dnsRegisteredDomains.Clear();
        UpdateSessionElapsed();
        UpdateTrafficLabels();
        UpdateContentLabels();
    }

    private void UpdateSessionElapsed()
    {
        var elapsed = DateTimeOffset.UtcNow - _sessionStartedAt;
        var hours = (int)elapsed.TotalHours;
        var minutes = elapsed.Minutes;
        var seconds = elapsed.Seconds;
        SessionElapsed = $"{hours}h {minutes}m {seconds}s";
    }

    private void UpdateTrafficStats(SocketTrafficEventArgs args)
    {
        if (args.SentDelta > 0)
        {
            _sessionBytesSent += args.SentDelta;
        }
        if (args.ReceivedDelta > 0)
        {
            _sessionBytesReceived += args.ReceivedDelta;
        }
        UpdateTrafficLabels();
    }

    private void UpdateTrafficLabels()
    {
        DataSent = FormatBytes(_sessionBytesSent);
        DataReceived = FormatBytes(_sessionBytesReceived);
    }

    private void UpdateContentLabels()
    {
        ContentDownloadedCount = $"{_contentDownloadedCount} arquivos";
        ContentPublishedCount = $"{_contentPublishedCount} arquivos";
        DnsRegisteredCount = $"{_dnsRegisteredCount} domínios";
    }

    private void IncrementContentDownloaded(string contentHash)
    {
        if (string.IsNullOrWhiteSpace(contentHash))
        {
            return;
        }
        if (_downloadedContentHashes.Add(contentHash))
        {
            _contentDownloadedCount++;
            UpdateContentLabels();
        }
    }

    private void IncrementContentPublished(string contentHash)
    {
        if (string.IsNullOrWhiteSpace(contentHash))
        {
            return;
        }
        if (_publishedContentHashes.Add(contentHash))
        {
            _contentPublishedCount++;
            UpdateContentLabels();
        }
    }

    private void IncrementDnsRegistered(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return;
        }
        if (_dnsRegisteredDomains.Add(domain))
        {
            _dnsRegisteredCount++;
            UpdateContentLabels();
        }
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024)
        {
            return $"{bytes} B";
        }
        var kb = bytes / 1024.0;
        if (kb < 1024)
        {
            return $"{kb:0.##} KB";
        }
        var mb = kb / 1024.0;
        if (mb < 1024)
        {
            return $"{mb:0.##} MB";
        }
        var gb = mb / 1024.0;
        return $"{gb:0.##} GB";
    }

    private void UpdatePowTotals(double elapsedSeconds)
    {
        _powSolvedTotal++;
        _powTotalSeconds += elapsedSeconds;
        PowSolvedCount = _powSolvedTotal.ToString();
        PowTotalTime = $"{(int)_powTotalSeconds}s";
    }

    private void ShowPowMonitor()
    {
        if (_owner is null || !_useUiDispatcher)
        {
            return;
        }

        if (_powMonitorWindow is null || !_powMonitorWindow.IsVisible)
        {
            _powMonitorWindow = new PowMonitorWindow
            {
                DataContext = this
            };
            _powMonitorWindow.Show(_owner);
        }
        else
        {
            _powMonitorWindow.Activate();
        }
    }

    private void CancelPowMonitorClose()
    {
        Interlocked.Increment(ref _powMonitorCloseVersion);
    }

    private void ClosePowMonitor()
    {
        if (!_useUiDispatcher)
        {
            return;
        }
        if (_powMonitorWindow is null)
        {
            return;
        }
        CancelPowMonitorClose();
        _powMonitorWindow.Close();
        _powMonitorWindow = null;
    }

    private void SchedulePowMonitorClose()
    {
        if (!_useUiDispatcher)
        {
            return;
        }
        if (_powMonitorWindow is null)
        {
            return;
        }

        var version = Interlocked.Increment(ref _powMonitorCloseVersion);
        _ = Dispatcher.UIThread.InvokeAsync(async () =>
        {
            await Task.Delay(2000);
            if (version != _powMonitorCloseVersion)
            {
                return;
            }
            if (_powMonitorWindow is null || IsPowActive)
            {
                return;
            }
            _powMonitorWindow.Close();
            _powMonitorWindow = null;
        });
    }

    private void CancelPow()
    {
        _powCts?.Cancel();
        PowStatus = "PoW cancelado";
        AppendPowLog("PoW cancelado pelo usuario.");
        IsPowActive = false;
        if (string.Equals(_importantFlowKind, "pow", StringComparison.OrdinalIgnoreCase))
        {
            MarkImportantFlowDone();
        }
        _ = Task.Run(TryRunDeferredAutoSignAsync);
        if (ShouldResumeContinuousMining())
        {
            _ = StartContinuousMiningAsync();
        }
    }

    private static Dictionary<string, object> NormalizePayload(Dictionary<string, object> payload)
    {
        var normalized = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in payload)
        {
            normalized[key] = NormalizeJsonValue(value);
        }
        return normalized;
    }

    private static object NormalizeJsonValue(object? value)
    {
        if (value is null)
        {
            return string.Empty;
        }
        if (value is JsonElement element)
        {
            return NormalizeJsonElement(element);
        }
        if (value is Dictionary<string, object> dict)
        {
            var result = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            foreach (var (key, inner) in dict)
            {
                result[key] = NormalizeJsonValue(inner);
            }
            return result;
        }
        if (value is IEnumerable<object> list)
        {
            return list.Select(NormalizeJsonValue).ToList();
        }
        return value;
    }

    private static object NormalizeJsonElement(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Object => element.EnumerateObject()
                .ToDictionary(p => p.Name, p => NormalizeJsonElement(p.Value), StringComparer.OrdinalIgnoreCase),
            JsonValueKind.Array => element.EnumerateArray().Select(NormalizeJsonElement).ToList(),
            JsonValueKind.String => element.GetString() ?? string.Empty,
            JsonValueKind.Number => element.TryGetInt64(out var l) ? l : element.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => string.Empty
        };
    }

    private void Back()
    {
        if (_historyIndex <= 0)
        {
            return;
        }

        _historyIndex--;
        BrowserUrl = _history[_historyIndex];
        _ = NavigateToAsync(BrowserUrl, false);
        RaiseCommandCanExecuteChanged();
    }

    private void Forward()
    {
        if (_historyIndex >= _history.Count - 1)
        {
            return;
        }

        _historyIndex++;
        BrowserUrl = _history[_historyIndex];
        _ = NavigateToAsync(BrowserUrl, false);
        RaiseCommandCanExecuteChanged();
    }

    private async Task ReloadAsync()
    {
        if (_historyIndex < 0 || _historyIndex >= _history.Count)
        {
            return;
        }

        await NavigateToAsync(_history[_historyIndex], false);
    }

    private void Home()
    {
        BrowserUrl = "hps://rede";
        _ = NavigateToAsync(BrowserUrl, true);
    }

    private async Task SelectUploadFileAsync()
    {
        if (_owner is null)
        {
            return;
        }

        var path = await _fileDialogService.OpenFileAsync(_owner, "Selecionar arquivo", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        UploadFilePath = path;
        if (string.IsNullOrWhiteSpace(UploadTitle))
        {
            UploadTitle = Path.GetFileNameWithoutExtension(path);
        }

        if (string.IsNullOrWhiteSpace(UploadMimeType))
        {
            UploadMimeType = _contentService.GuessMimeType(path);
        }
    }

    private async Task RefreshNetworkAsync()
    {
        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            NetworkStatus = "Conecte-se à rede primeiro.";
            return;
        }

        NetworkStatus = "Atualizando rede...";
        await _socketClient.EmitAsync("get_network_state", new { });
        await _socketClient.EmitAsync("get_network_nodes", new { });
        await _socketClient.EmitAsync("get_servers", new { });
    }

    private async Task SyncNetworkAsync()
    {
        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            NetworkStatus = "Conecte-se à rede primeiro.";
            return;
        }

        NetworkStatus = "Sincronizando rede...";
        await _socketClient.EmitAsync("get_servers", new { });
        var servers = KnownServers.Select(s => s.Address).Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
        await _socketClient.EmitAsync("sync_servers", new { servers });
        await SyncClientFilesAsync();
        await SyncClientDnsFilesAsync();
        await SyncClientContractsAsync();
        NetworkStatus = "Sincronização concluída.";
    }

    private async Task ShowMyNodeAsync()
    {
        var info = $"ID do Nó: {NodeId}\n" +
                   $"ID do Cliente: {ClientId}\n" +
                   $"ID da Sessão: {SessionId}\n" +
                   $"Usuário: {User}\n" +
                   $"Reputação: {Reputation}\n" +
                   $"Conectado: {(IsLoggedIn && _socketClient.IsConnected ? "Sim" : "Não")}\n" +
                   $"Servidor: {ServerAddress}";
        if (_owner is null)
        {
            NetworkStatus = info.Replace("\n", " | ");
            return;
        }
        await _promptService.ConfirmAsync(_owner, "Meu Nó", info, "OK", "Fechar");
    }

    private async Task RefreshSelectedInventoryAsync()
    {
        if (SelectedNetworkNode is null)
        {
            _remotePublishedInventory.Clear();
            _remoteLocalInventory.Clear();
            InventoryStatus = string.Empty;
            return;
        }

        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            InventoryStatus = "Conecte-se à rede primeiro.";
            return;
        }

        if (string.IsNullOrWhiteSpace(SelectedNetworkNode.Username))
        {
            InventoryStatus = "Usuário do nó indisponível.";
            return;
        }

        _remotePublishedInventory.Clear();
        _remoteLocalInventory.Clear();
        _pendingInventoryRequestId = Guid.NewGuid().ToString();
        InventoryStatus = $"Solicitando inventório de {SelectedNetworkNode.Username}...";
        await _socketClient.EmitAsync("request_inventory", new
        {
            target_user = SelectedNetworkNode.Username,
            request_id = _pendingInventoryRequestId
        });
    }

    private async Task RequestInventoryTransferAsync(InventoryItem item)
    {
        if (!IsLoggedIn || !_socketClient.IsConnected)
        {
            InventoryStatus = "Conecte-se à rede primeiro.";
            return;
        }

        if (item is null || string.IsNullOrWhiteSpace(item.ContentHash))
        {
            InventoryStatus = "Item de inventório inválido.";
            return;
        }

        if (string.Equals(item.Owner, User, StringComparison.OrdinalIgnoreCase))
        {
            InventoryStatus = "Você já possui este item.";
            return;
        }

        var owner = string.IsNullOrWhiteSpace(item.Owner) ? SelectedNetworkNode?.Username ?? string.Empty : item.Owner;
        if (string.IsNullOrWhiteSpace(owner))
        {
            InventoryStatus = "Dono do item não informado.";
            return;
        }

        if (TryBuildSpendPayment("inventory_transfer", 1, out var payment))
        {
            InventoryStatus = "Enviando solicitação de inventório com pagamento HPS...";
            await SendInventoryTransferRequestAsync(item, owner, null, null, payment);
            return;
        }

        _pendingInventoryTransfer = new PendingInventoryTransfer(item, owner);
        InventoryStatus = "Solicitando PoW para transferência de inventório...";
        await RequestPowChallengeAsync("inventory_transfer");
    }

    public Task RequestInventoryTransferFromUiAsync(InventoryItem item)
    {
        return RequestInventoryTransferAsync(item);
    }

    private Task RequestSelectedInventoryTransferAsync()
    {
        if (SelectedRemoteInventoryItem is null)
        {
            InventoryStatus = "Selecione um item do inventório do nó.";
            return Task.CompletedTask;
        }
        return RequestInventoryTransferAsync(SelectedRemoteInventoryItem);
    }

    private async Task SendInventoryTransferRequestAsync(InventoryItem item, string owner, ulong? powNonce, double? hashrate, object? hpsPayment)
    {
        await _socketClient.EmitAsync("request_inventory_transfer", new
        {
            target_user = owner,
            content_hash = item.ContentHash,
            title = item.Title,
            description = item.Description,
            mime_type = item.MimeType,
            size = item.Size,
            pow_nonce = powNonce?.ToString() ?? string.Empty,
            hashrate_observed = hashrate ?? 0.0,
            hps_payment = hpsPayment
        });
    }

    private void HandleUploadResult(JsonElement payload, bool countAsPublished)
    {
        if (payload.TryGetProperty("pending", out var pendingProp) && pendingProp.GetBoolean())
        {
            var message = payload.TryGetProperty("message", out var msgProp) ? msgProp.GetString() : "Transação em análise.";
            UploadStatus = message ?? "Transação em análise.";
            if (_contentPublishResultTcs is not null && !_contentPublishResultTcs.Task.IsCompleted)
            {
                _contentPublishResultTcs.TrySetResult(new PublishContentResult(false, string.Empty, message ?? "Transação em análise."));
            }
            MovePendingHpsPaymentToWalletSync("upload");
            return;
        }

        var success = payload.TryGetProperty("success", out var successProp) && successProp.GetBoolean();
        if (success)
        {
            var hash = payload.TryGetProperty("content_hash", out var hashProp) ? hashProp.GetString() : string.Empty;
            UploadHash = hash ?? string.Empty;
            UploadStatus = $"Upload concluído: {hash}";
            if (_contentPublishResultTcs is not null && !_contentPublishResultTcs.Task.IsCompleted)
            {
                _contentPublishResultTcs.TrySetResult(new PublishContentResult(true, hash ?? string.Empty, string.Empty));
            }
            RememberPublishedContent(hash ?? string.Empty);
            ClearPendingHpsPayment("upload");
            RaiseCommandCanExecuteChanged();
            if (countAsPublished && !string.IsNullOrWhiteSpace(hash))
            {
                IncrementContentPublished(hash);
            }
            if (!string.IsNullOrWhiteSpace(_pendingTransferUploadId))
            {
                TransferStatus = $"Transferência aceita. Hash: {hash}";
                AppendImportantFlowLog($"Transferência concluída: {hash}");
                _pendingTransferUploadId = null;
                if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
            }
        }
        else
        {
            var error = payload.TryGetProperty("error", out var errProp) ? errProp.GetString() : "Erro desconhecido";
            UploadStatus = $"Falha no upload: {error}";
            if (_contentPublishResultTcs is not null && !_contentPublishResultTcs.Task.IsCompleted)
            {
                _contentPublishResultTcs.TrySetResult(new PublishContentResult(false, string.Empty, error ?? "Erro desconhecido"));
            }
            ReleasePendingHpsPayment("upload");
            if (!string.IsNullOrWhiteSpace(_pendingTransferUploadId))
            {
                TransferStatus = $"Falha ao aceitar transferência: {error}";
                AppendImportantFlowLog($"Falha na transferência: {error}");
                _pendingTransferUploadId = null;
                if (string.Equals(_importantFlowKind, "transfer", StringComparison.OrdinalIgnoreCase))
                {
                    MarkImportantFlowDone();
                }
            }
        }
        _ = Task.Run(TryRunDeferredAutoSignAsync);
        if (ShouldResumeContinuousMining())
        {
            _ = StartContinuousMiningAsync();
        }
    }

    private async Task UploadAsync()
    {
        if (!_socketClient.IsConnected)
        {
            UploadStatus = "Conecte-se à rede primeiro.";
            return;
        }

        if (_privateKey is null)
        {
            UploadStatus = "Chave privada não disponível.";
            return;
        }

        if (string.IsNullOrWhiteSpace(UploadFilePath) || !File.Exists(UploadFilePath))
        {
            UploadStatus = "Arquivo inválido.";
            return;
        }

        if (string.IsNullOrWhiteSpace(UploadTitle))
        {
            UploadStatus = "Informe um título.";
            return;
        }

        var fileInfo = new FileInfo(UploadFilePath);
        if (fileInfo.Length > MaxUploadSize)
        {
            UploadStatus = $"Arquivo muito grande (max {MaxUploadSize / (1024 * 1024)}MB).";
            return;
        }

        var content = await File.ReadAllBytesAsync(UploadFilePath);
        var contentHash = _contentService.ComputeSha256HexBytes(content);
        UploadHash = contentHash;
        var signature = _privateKey.SignData(content, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var signatureB64 = Convert.ToBase64String(signature);
        var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));

        var details = new Dictionary<string, string>
        {
            { "FILE_NAME", Path.GetFileName(UploadFilePath) },
            { "FILE_SIZE", content.Length.ToString() },
            { "FILE_HASH", contentHash },
            { "TITLE", UploadTitle },
            { "MIME", UploadMimeType },
            { "DESCRIPTION", UploadDescription },
            { "PUBLIC_KEY", publicKeyB64 }
        };

        var actionType = "upload_file";
        var transferTo = string.Empty;
        var transferType = string.Empty;
        var transferApp = string.Empty;

        if (string.Equals(UploadTitle, DnsChangeTitle, StringComparison.Ordinal))
        {
            var (domain, newOwner, error) = ParseDnsChangeManifest(content);
            if (!string.IsNullOrWhiteSpace(error))
            {
                UploadStatus = error;
                return;
            }
            details["DOMAIN"] = domain;
            transferTo = newOwner;
            transferType = "domain";
            actionType = "transfer_domain";
        }
        else
        {
            var (tType, tTo, tApp) = ParseTransferTitle(UploadTitle);
            if (!string.IsNullOrWhiteSpace(tType))
            {
                transferType = tType;
                transferTo = tTo;
                transferApp = tApp;
                if (string.Equals(transferType, "file", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(transferType, "content", StringComparison.OrdinalIgnoreCase))
                {
                    actionType = "transfer_content";
                }
                else if (string.Equals(transferType, "api_app", StringComparison.OrdinalIgnoreCase))
                {
                    actionType = "transfer_api_app";
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(transferTo))
        {
            details["TRANSFER_TO"] = transferTo;
        }
        if (!string.IsNullOrWhiteSpace(transferType))
        {
            details["TRANSFER_TYPE"] = transferType;
        }
        if (!string.IsNullOrWhiteSpace(transferApp))
        {
            details["APP"] = transferApp;
        }

        if ((actionType == "transfer_content" || actionType == "transfer_api_app" || actionType == "transfer_domain") &&
            string.IsNullOrWhiteSpace(transferTo))
        {
            UploadStatus = "Informe o usuário destino para a transferência.";
            return;
        }
        if (actionType == "transfer_domain" && !details.ContainsKey("DOMAIN"))
        {
            UploadStatus = "Arquivo DNS change inválido: domínio ausente.";
            return;
        }

        var contractText = _contentService.BuildContractTemplate(actionType, details);

        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);
        var fullContent = _contentService.CombineBytes(content, Encoding.UTF8.GetBytes(signedContract));
        var fullContentB64 = Convert.ToBase64String(fullContent);

        _contentService.SaveContentToStorage(contentHash, content, UploadTitle, UploadDescription, UploadMimeType, signatureB64, publicKeyB64, User);
        SaveLocalPublishedContract(actionType, contentHash, details.TryGetValue("DOMAIN", out var domainValue) ? domainValue : string.Empty, signedContract);
        LoadLocalInventory();

        _pendingUpload = new PendingUpload(
            contentHash,
            UploadTitle,
            UploadDescription,
            UploadMimeType,
            content.Length,
            signatureB64,
            publicKeyB64,
            fullContentB64
        );

        UploadStatus = "Preparando upload...";
        await RunPowOrHpsAsync(
            "upload",
            () =>
            {
                UploadStatus = "Solicitando PoW para upload...";
                return RequestPowChallengeAsync("upload");
            },
            payment =>
            {
                UploadStatus = "Enviando upload com pagamento HPS...";
                return SubmitPendingUploadAsync(0, 0.0, payment.Payload);
            },
            null
        );
    }

    private async Task CopyUploadHashAsync()
    {
        if (string.IsNullOrWhiteSpace(UploadHash))
        {
            return;
        }
        var clipboard = ResolveClipboard();
        if (clipboard is null)
        {
            UploadStatus = "Área de transferência indisponível.";
            return;
        }
        try
        {
            await clipboard.SetTextAsync(UploadHash.Trim());
            UploadStatus = "Hash copiado para a área de transferência.";
        }
        catch (Exception ex)
        {
            UploadStatus = $"Falha ao copiar hash: {ex.Message}";
        }
    }

    private Avalonia.Input.Platform.IClipboard? ResolveClipboard()
    {
        if (_owner is null)
        {
            return null;
        }

        return TopLevel.GetTopLevel(_owner)?.Clipboard;
    }

    private async Task SaveContentAsync()
    {
        if (_owner is null || _lastContentBytes is null)
        {
            return;
        }

        var extension = GetPreferredExtension(_lastContentMime, _lastContentTitle);
        var defaultName = BuildDefaultDownloadName(_lastContentTitle, extension);
        var outputPath = await _fileDialogService.SaveFileAsync(
            _owner,
            "Salvar conteúdo",
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            defaultName
        );
        if (string.IsNullOrWhiteSpace(outputPath))
        {
            return;
        }

        if (!Path.HasExtension(outputPath) && !string.IsNullOrWhiteSpace(extension))
        {
            outputPath += extension;
        }

        var bytesToSave = RemoveTrailingHpsContract(_lastContentBytes);
        await File.WriteAllBytesAsync(outputPath, bytesToSave);
    }

    private void UpdateActionQueueStatus(string action, string status, int position)
    {
        if (string.IsNullOrWhiteSpace(action) || string.IsNullOrWhiteSpace(status))
        {
            return;
        }

        var statusLower = status.Trim().ToLowerInvariant();
        var actionLower = action.Trim().ToLowerInvariant();
        var queueMessage = statusLower switch
        {
            "queued" when position > 0 => $"Na fila (posição {position})...",
            "queued" => "Na fila (sem espera no momento).",
            "processing" => "Processando agora...",
            "done" => "Processamento concluído.",
            _ => string.Empty
        };
        if (string.IsNullOrWhiteSpace(queueMessage))
        {
            return;
        }

        switch (actionLower)
        {
            case "authenticate":
                LoginStatus = queueMessage;
                break;
            case "publish_content":
                UploadStatus = queueMessage;
                break;
            case "register_dns":
                DnsStatus = queueMessage;
                break;
            case "transfer_hps":
                HpsActionStatus = queueMessage;
                break;
            case "accept_usage_contract":
                LoginStatus = queueMessage;
                break;
        }

        var queueDetails = "O servidor processa ações em fila, mesmo quando não há espera.";
        if (!string.Equals(_importantFlowKind, "queue", StringComparison.OrdinalIgnoreCase))
        {
            StartImportantFlow("Fila do servidor", queueMessage, queueDetails, "queue");
        }
        else
        {
            UpdateImportantFlowStatus(queueMessage);
        }
        if (string.Equals(statusLower, "done", StringComparison.OrdinalIgnoreCase))
        {
            MarkImportantFlowDone();
        }
    }

    private static string BuildDefaultDownloadName(string title, string preferredExtension)
    {
        var sanitized = SanitizeFileName(title);
        if (string.IsNullOrWhiteSpace(sanitized))
        {
            sanitized = "hps_content";
        }

        if (!Path.HasExtension(sanitized) && !string.IsNullOrWhiteSpace(preferredExtension))
        {
            sanitized += preferredExtension;
        }
        return sanitized;
    }

    private static string SanitizeFileName(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return string.Empty;
        }

        var invalidChars = Path.GetInvalidFileNameChars();
        var cleaned = new string(fileName.Trim().Select(c => invalidChars.Contains(c) ? '_' : c).ToArray());
        return cleaned.Trim();
    }

    private static string GetPreferredExtension(string mimeType, string title)
    {
        if (!string.IsNullOrWhiteSpace(title))
        {
            var titleExt = Path.GetExtension(title.Trim());
            if (!string.IsNullOrWhiteSpace(titleExt))
            {
                return titleExt;
            }
        }

        var normalized = (mimeType ?? string.Empty).Trim().ToLowerInvariant();
        return normalized switch
        {
            "application/pdf" => ".pdf",
            "application/json" => ".json",
            "application/xml" => ".xml",
            "application/zip" => ".zip",
            "application/gzip" => ".gz",
            "application/x-tar" => ".tar",
            "application/octet-stream" => ".dat",
            "text/plain" => ".txt",
            "text/html" => ".html",
            "text/css" => ".css",
            "text/csv" => ".csv",
            "text/markdown" => ".md",
            "image/png" => ".png",
            "image/jpeg" => ".jpg",
            "image/gif" => ".gif",
            "image/webp" => ".webp",
            "audio/mpeg" => ".mp3",
            "audio/wav" => ".wav",
            "video/mp4" => ".mp4",
            "video/webm" => ".webm",
            _ => string.Empty
        };
    }

    private static byte[] RemoveTrailingHpsContract(byte[] content)
    {
        if (content.Length == 0)
        {
            return content;
        }

        var markerBytes = Encoding.UTF8.GetBytes("\n# HSYST P2P SERVICE\n## CONTRACT:");
        var markerIndex = LastIndexOfSequence(content, markerBytes);
        if (markerIndex <= 0)
        {
            return content;
        }

        var suffixLength = content.Length - markerIndex;
        if (suffixLength <= 0)
        {
            return content;
        }

        var contractText = Encoding.UTF8.GetString(content, markerIndex + 1, suffixLength - 1).Trim();
        if (!contractText.StartsWith("# HSYST P2P SERVICE", StringComparison.Ordinal) ||
            !contractText.Contains("## CONTRACT:", StringComparison.Ordinal) ||
            !contractText.Contains("## :END CONTRACT", StringComparison.Ordinal))
        {
            return content;
        }

        var cleanBytesLength = markerIndex;
        if (cleanBytesLength <= 0 || cleanBytesLength > content.Length)
        {
            return content;
        }

        var clean = new byte[cleanBytesLength];
        Buffer.BlockCopy(content, 0, clean, 0, cleanBytesLength);
        return clean;
    }

    private static int LastIndexOfSequence(byte[] source, byte[] pattern)
    {
        if (source.Length == 0 || pattern.Length == 0 || pattern.Length > source.Length)
        {
            return -1;
        }

        for (var i = source.Length - pattern.Length; i >= 0; i--)
        {
            var matched = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                if (source[i + j] != pattern[j])
                {
                    matched = false;
                    break;
                }
            }
            if (matched)
            {
                return i;
            }
        }

        return -1;
    }

    private async Task RegisterDnsAsync()
    {
        if (string.IsNullOrWhiteSpace(DnsDomain) || string.IsNullOrWhiteSpace(DnsContentHash))
        {
            return;
        }

        if (!_socketClient.IsConnected)
        {
            DnsStatus = "Conecte-se à rede primeiro.";
            return;
        }

        if (string.IsNullOrWhiteSpace(User) || User == "Não logado")
        {
            DnsStatus = "Faça login para registrar DNS.";
            return;
        }

        DnsStatus = "Registro DNS em andamento...";
        if (_privateKey is null)
        {
            DnsStatus = "Chave privada não disponível";
            return;
        }

        var domain = DnsDomain.Trim().ToLowerInvariant();
        var contentHash = NormalizeContentHash(DnsContentHash);
        if (string.IsNullOrWhiteSpace(contentHash))
        {
            DnsStatus = "Hash de conteúdo inválido (use o hash de 64 caracteres).";
            return;
        }
        if (!IsValidDomain(domain))
        {
            DnsStatus = "Domínio inválido";
            return;
        }

        var contractText = _contentService.BuildContractTemplate("register_dns", new Dictionary<string, string>
        {
            { "DOMAIN", domain },
            { "CONTENT_HASH", contentHash },
            { "PUBLIC_KEY", Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem)) }
        });

        var signedContract = _contentService.ApplyContractSignature(contractText, _privateKey, User);
        var ddnsContent = _contentService.CreateDdnsFile(domain, contentHash, User, PublicKeyPem);
        var ddnsContentFull = _contentService.CombineBytes(ddnsContent, Encoding.UTF8.GetBytes(signedContract));
        var ddnsHash = _contentService.ComputeSha256HexBytes(ddnsContent);

        var signature = _contentService.SignDdnsPayload(ddnsContent, _privateKey);
        var signatureB64 = Convert.ToBase64String(signature);
        var publicKeyB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(PublicKeyPem));

        _contentService.SaveDdnsToStorage(domain, ddnsContent, ddnsHash, contentHash, User, signatureB64, publicKeyB64);

        _pendingDns = new PendingDnsRegistration(
            domain,
            ddnsContentFull,
            signatureB64,
            publicKeyB64
        );

        DnsStatus = "Preparando registro DNS...";
        StartImportantFlow("Registro DNS", "Preparando registro DNS...", $"Domínio: {domain}\nHash: {contentHash}", "dns");
        await RunPowOrHpsAsync(
            "dns",
            () =>
            {
                DnsStatus = "Solicitando PoW para registro DNS...";
                UpdateImportantFlowStatus("Solicitando PoW para registro DNS...");
                return RequestPowChallengeAsync("dns");
            },
            payment =>
            {
                DnsStatus = "Enviando registro DNS com pagamento HPS...";
                UpdateImportantFlowStatus("Enviando registro DNS com pagamento HPS...");
                return SubmitPendingDnsAsync(0, 0.0, payment.Payload);
            },
            null
        );
    }

    private static bool IsValidDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return false;
        }

        foreach (var c in domain)
        {
            var ok = (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') ||
                     c == '-' || c == '.';
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

}
