/*
 * AIAuditor.java
 * Author: Richard Hyunho Im (@richeeta), Route Zero Security
 * Contributors: Vinaya Kumar ([@V9Y1nf0S3C](https://github.com/V9Y1nf0S3C))

 * Core class for the AI Auditor Burp Suite extension. 
 * This class integrates with multiple Large Language Models (LLMs) to 
 * analyze HTTP requests and responses for security vulnerabilities. 
 * It manages API interactions, processes findings, and provides detailed
 * results for integration into Burp Suite's Scanner and other tools.
 * 
 * Version: 1.0
 * 
 * CHANGELOG: December 2, 2024
 * - FIXED: All models should correctly report issues in the Scanner now.
 * - FIXED: All API keys should now validate correctly.
 * - FIXED: Saved API keys should now persist on restart.
 * 
 * Version: 1.1
 * 
 * CHANGELOG: July 09, 2025
 * - ADDED: Timestamp on logs
 * - ADDED: Gemini models updated with latest.
 * - ADDED: Input controls on UI to contrl data
 * - ADDED: Verbose logging for troubleshooting
 * - ADDED: You can now connect the plugin to a local LM Studio server, enabling the use of local Large Language Models, enhanced privacy.
 * - ADDED: Added a set of "click-to-copy" prompt templates to streamline your workflow.
 * - ADDED: Proxying through dynamic value (self port like lcoalhsot:8080)
 * - MODIFIED: Token logic changed to 4 chars per token & 'Estimated total tokens' is shown on logs.
 * - ADDED: Batch size UI with limit 1-30 is added for performance tuning, Delay to be reduyced
 * - ADDED: StatusPanel for Active Tasks, Queued Tasks, Completed Tasks to know what is going on  
 * - ADDED: 3 different levels of logging is enabled and UI added
 * - MODIFIED: Make the UI window scrollable, good for small screens
 * - ADDED: Rate limmit button is added to Rate limit (useful in calling free API's)
 * - ADDED: buttons added for tokens length
 * - MODIFIED: Message box are disabled and the message text is added to Burp Event Log instead
 * - ADDED: Dynamic model loading - worked for gemini
 * - ADDED: API for Openroute models are added
 * - ADDED: Model model loading and model filtering is implemented.
 * - ADDED: Dynamic Models loading based on the valid API keys. User can use any latest model
 * - ADDED: RightClick > Explain me this is added. Vulnrabilities will be added as Inforamtion items to read. Custom & dedicated prompt is also provided for user inputs
 * - ADDED: Multiple Gemini API keys can be added and they will be rotated when rate limits triggered. Good for using free api keys to try out the plugins
 * - MODIFIED: When the custom prompt dont have format related instructions, model will add them dynamically in the prompt so the findings will be added to burp.
 *
 * Version: 1.2
 *
 * CHANGELOG: August 31, 2026
 * - ADDED: Chat tab to prompt the local LLM from inside Burp (Ctrl/Cmd+Enter). Falls back to Premium Model for PoCs if no Local LLM URL is set. Right-click Send to Chat attaches HTTP or issue context.
 *
 * Version: 1.3
 *
 * CHANGELOG: September 1, 2026
 * - MODIFIED: Suite UI — no nested scroll, no always-on how-to banner, Save on a footer, Automation tab (was Cheap local bulk), collapsed setup guide, theme-aware logs, dead business-logic drawer removed.
 * - ADDED: Chat Checks buttons (Email forms, Secrets, Auth, IDOR, XSS, Hidden APIs) that hunt the Site Map with Include Burp traffic on.
 */

package burp;

import java.net.Proxy;
import java.net.InetSocketAddress;
import javax.net.ssl.*;
import java.util.Objects;

import java.time.format.DateTimeFormatter;
import java.time.ZoneId;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.awt.event.ItemEvent;
import java.util.*;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
 
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import burp.api.montoya.core.Range;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.Interaction;
import burp.api.montoya.collaborator.InteractionFilter;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.*;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
 
import javax.swing.*;
import java.awt.*;
 
public class AIAuditor implements BurpExtension, ContextMenuItemsProvider, ScanCheck, HttpHandler {
    private static final String EXTENSION_NAME = "AI Auditor";

	 private int maxRetries;
	 private int retryDelayMs;
    private int maxChunkSize;
    private int rateLimitCount;
    private int rateLimitWindow;
	private int batchSize;

    private static final String PREF_PREFIX = "ai_auditor.";

    /**
     * Old UI copy; not a valid {@code model} for Ollama's OpenAI-compatible API (Ollama expects tags such as
     * {@code gemma4:e4b} from {@code ollama list}).
     */
    private static final String LEGACY_LOCAL_MODEL_PLACEHOLDER = "local-llm (LM Studio)";
    /** Shown in the Local LLM model id combo before any /v1/models refresh (Ollama-style tags). */
    private static final String[] LOCAL_LLM_MODEL_ID_PRESETS = {"gemma4:e4b", "gemma4:26b"};

    /** Anthropic Messages API: room for structured JSON findings without truncating mid-response. */
    private static final int CLAUDE_MAX_OUTPUT_TOKENS = 8192;

    private static final int PASSIVE_AUDIT_DEDUP_MAX_KEYS = 8000;
    private static final int DEFAULT_PASSIVE_MAX_BODY_KB = 256;
    /** Cap auto-executed PoC requests extracted from model output. */
    private static final int MAX_AUTO_POC_REQUESTS = 8;
    /** Per-response body excerpt included in auto-execution and verification prompts. */
    private static final int POC_RESPONSE_BODY_PREVIEW_CHARS = 12_000;
    /** Total cap for all response excerpts sent to the PoC verification LLM call. */
    private static final int POC_VERIFY_TOTAL_RESPONSE_CHARS = 48_000;
    /**
     * PoC/investigation prompts are not chunked; cap evidence to avoid single-request provider hard-limit failures.
     * Uses a soft target tied to maxChunkSize and a hard ceiling for safety.
     */
    private static final int POC_PROMPT_MIN_EVIDENCE_TOKENS = 20000;
    private static final int POC_PROMPT_HARD_CAP_TOKENS = 180000;
    /** Limit premium verification calls per parsed response to control cost/latency. */
    private static final int MAX_PREMIUM_VERIFY_PER_RESPONSE = 4;
    private static final long TIMING_SQLI_DELAY_MS = 4500L;
    private static final long TIMING_SQLI_THRESHOLD_MS = 3000L;
    private static final int OOB_POLL_ROUNDS = 5;
    private static final long OOB_POLL_SLEEP_MS = 1200L;
    /** Hidden guardrails for always-on active checks. */
    private static final int ACTIVE_SCAN_MAX_REQUESTS_PER_INSERTION = 12;
    private static final int ACTIVE_SCAN_MAX_REQUESTS_PER_HOST_WINDOW = 90;
    private static final long ACTIVE_SCAN_HOST_WINDOW_MS = 60_000L;

    /** Validation HTTP calls use short timeouts so the UI does not hang on unreachable hosts. */
    private static final int VALIDATION_CONNECT_MS = 15000;
    private static final int VALIDATION_READ_MS = 25000;
    /** Request timeout defaults: keep cloud responsive while allowing slower local model generation. */
    private static final int AI_CONNECT_TIMEOUT_MS = 15000;
    private static final int AI_READ_TIMEOUT_CLOUD_MS = 90000;
    private static final int AI_READ_TIMEOUT_LOCAL_MS = 360000;

    private static final String PROXY_BROWSER_LOCAL_AI_TOOLTIP =
            "Unlike “broad passive HTTP”, this is only responses from Burp’s Proxy tool (and Repeater if enabled) — i.e. traffic sent through your listener, not every passive-scan hit site-wide. "
            + "Cheap automation: uses the Connect automatic/bulk model and Local LLM model id, never the Premium PoC model. "
            + "Runs only if bulk model is local/… and Local LLM URL is set — otherwise this checkbox does nothing. "
            + "Queues the same audit as a manual scan at browser pace.";

    private static final String LOCAL_LM_STUDIO_SETUP_TEXT =
            "— Terminal path: Ollama + Gemma 4 (e.g. E4B) —\n\n"
            + "Install and start Ollama (macOS, Homebrew):\n"
            + "  brew install ollama\n"
            + "  ollama serve\n"
            + "(Leave that running, or use: brew services start ollama)\n"
            + "Use a second terminal for:\n"
            + "  ollama pull gemma4:e4b\n"
            + "If pull fails, update Ollama to the latest version.\n\n"
            + "In AI Auditor → Connect → Models:\n"
            + "  Local LLM URL:  http://127.0.0.1:11434/v1\n"
            + "  Click Validate (next to the URL).\n"
            + "  Automatic / bulk model:  local/local-llm (LM Studio) or local/<tag> from Get Latest Models\n"
            + "  Local LLM model id:  gemma4:e4b  (must match `ollama list` on that host)\n"
            + "  Get Latest Models if the dropdown is empty, then Save Settings.\n\n"
            + "— GUI path: LM Studio —\n\n"
            + "1) Install LM Studio (lmstudio.ai), open Search, load Gemma 4 (or similar) if you prefer the GUI over Ollama.\n"
            + "2) Load the model → Local Server → Start Server (URL is often http://127.0.0.1:1234/v1).\n"
            + "3) Paste URL into Local LLM URL on Connect; Validate; set Local LLM model id to the loaded model id; Save.\n"
            + "4) On this tab, enable \"Proxied traffic only (Proxy ± Repeater): bulk model\" "
            + "if you want bulk LLM review of browser (or Repeater) traffic through Burp — local bulk + URL required.\n"
            + "5) Optional: Burp proxy at 127.0.0.1:8080 while this extension still uses the LM URL above — "
            + "requests to the LM host are skipped to avoid feedback loops.\n"
            + "6) If you set HTTP proxy under Tuning for cloud APIs, localhost and your local LLM host still go direct.\n";
     
     private MontoyaApi api;
     private PersistedObject persistedData;
     private ThreadPoolManager threadPoolManager;
    private CollaboratorClient collaboratorClient;
     private volatile boolean isShuttingDown = false;
     
     // UI Components
    private JPanel mainPanel;
    private JPasswordField openaiKeyField;
    private JTextArea geminiKeyField; // Changed to JTextArea for multiple keys
    private JPasswordField claudeKeyField;
    private JPasswordField openrouterKeyField;
    private JPasswordField xaiKeyField;

    private List<String> geminiApiKeys = new ArrayList<>();
    private AtomicInteger currentGeminiKeyIndex = new AtomicInteger(0);
    private JTextField localEndpointField;
    private JPasswordField localKeyField;
    /** Inline status above API keys — cloud Validate uses this so feedback is visible without opening Extension Output. */
    private JLabel cloudApiValidationStatusLabel;

    /** Inline status shown under Local LLM URL Validate button. */
    private JLabel localLlmValidationStatusLabel;
    /** Models for automatic paths: Scanner issues, Proxy/Repeater browser capture, passive crawl-all. */
    private JComboBox<String> automaticAuditModelDropdown;
    /** Models for manual actions: right-click scan, PoC, Explain, issue deep-dive from context menu. */
    private JComboBox<String> manualInvestigationModelDropdown;
    private JTextField filterModelsField;
     private JTextArea promptTemplateArea;
     private JTextArea explainMeThisPromptArea; // New field for Explain Me This custom prompt
     private JTextArea pocPromptArea;
     private JButton saveButton;
    private Registration menuRegistration;
    private Registration scanCheckRegistration;
    private Registration auditIssueHandlerRegistration;
    private Registration httpHandlerRegistration;
     private JTextField proxyField;
	 private JLabel activeTasksLabel;
	 private JLabel queuedTasksLabel;
	 private JLabel completedTasksLabel;
    /** Rolling log on the Dashboard tab (PoC, manual audits, passive hooks). */
    private JTextArea dashboardActivityArea;
    private static final int DASHBOARD_ACTIVITY_MAX_LINES = 400;

    /** Suite tab strip so Chat can be focused after a context-menu attach. */
    private JTabbedPane suiteTabs;
    private JTextArea chatHistoryArea;
    private JTextArea chatInputArea;
    private JButton chatSendButton;
    private JLabel chatStatusLabel;
    private JLabel chatAttachmentLabel;
    private JCheckBox chatIncludeHttpCheckbox;
    private final List<JButton> chatCheckButtons = new ArrayList<>();
    private volatile HttpRequestResponse chatAttachedHttp;
    private volatile String chatAttachedExtra;
    private final List<ChatTurn> chatTurns = new ArrayList<>();
    private volatile boolean chatBusy = false;
    private static final int CHAT_PROMPT_MAX_CHARS = 120_000;
    private static final int CHAT_HISTORY_MAX_TURNS = 24;
    private static final int CHAT_HISTORY_SCAN_MAX_ITEMS = 400;
    private static final int CHAT_SITEMAP_BODY_SCAN_MAX = 80;
    private static final int CHAT_QUERY_MATCH_LIST_MAX = 250;
    private static final int CHAT_DIGEST_MAX_CHARS = 60_000;
    private static final int CHAT_HTML_SCAN_CHARS = 80_000;
    private static final int CHAT_MAX_BODY_BYTES = 256 * 1024;
    private static final long CHAT_SCAN_BUDGET_MS = 8000L;
    private static final Set<String> CHAT_STOPWORDS = Set.of(
            "please", "look", "looking", "find", "search", "scan", "for", "the", "and", "that", "this",
            "with", "from", "have", "there", "their", "what", "when", "where", "which", "would",
            "could", "should", "about", "into", "over", "just", "like", "want", "need", "does",
            "sitemap", "site", "map", "burp", "chat", "traffic", "history", "proxy", "request",
            "response", "http", "https", "something", "specific", "related", "not", "all", "can",
            "you", "our", "plugin", "well", "huge", "items", "item", "also", "any", "are", "was",
            "were", "been", "being", "them", "then", "than", "some", "more", "most", "only",
            "through", "using", "use", "used", "see", "show", "tell", "give", "get", "got");
    private static final String[][] CHAT_VULN_CHECKS = {
            {"Email forms",
                    "Search the Site Map and JavaScript for non-authentication forms that collect email "
                            + "(newsletter, contact, marketing, support — not login, register, or forgot-password). "
                            + "List method, URL, and field names from evidence only. Say if none."},
            {"Secrets",
                    "Search JavaScript, HTML, and JSON in the Site Map for leaked secrets: API keys, JWTs, tokens, "
                            + "passwords, cloud credentials, private URLs. Quote the file URL and a short redacted snippet. "
                            + "Skip likely false positives."},
            {"Auth",
                    "Find authentication and session surfaces: login, register, password reset, OAuth, SSO, logout, cookies. "
                            + "Note anything unusual in evidence (verb tampering, missing CSRF, username enumeration, "
                            + "unverified identity-change flows). List method and URL."},
            {"IDOR",
                    "Find endpoints whose URLs or parameters look like object IDs (user, account, order, uuid, numeric id). "
                            + "List IDOR/BOLA candidates with method and URL. Do not invent IDs that are not in evidence."},
            {"XSS",
                    "Find reflected-input surfaces: search, q, query, redirect, next, callback, template, message. "
                            + "List method, URL, and parameter names worth XSS testing. Note sinks visible in JavaScript."},
            {"Hidden APIs",
                    "Find non-obvious APIs and debug surfaces: graphql, swagger, openapi, /api/, admin, actuator, "
                            + "source maps, env, backup, .json. List method and URL from the Site Map."}
    };
    private static final Pattern HTML_FORM_PATTERN = Pattern.compile("(?is)<form\\b[^>]*>.*?</form>");
    private static final Pattern HTML_EMAIL_INPUT_PATTERN = Pattern.compile(
            "(?is)<input\\b[^>]*(?:type\\s*=\\s*['\"]email['\"]|name\\s*=\\s*['\"][^'\"]*e-?mail[^'\"]*['\"])[^>]*>");
    private static final Pattern FORM_ACTION_PATTERN = Pattern.compile("(?is)\\baction\\s*=\\s*['\"]([^'\"]*)['\"]");
    private static final Pattern FORM_METHOD_PATTERN = Pattern.compile("(?is)\\bmethod\\s*=\\s*['\"]([^'\"]*)['\"]");
    private static final Pattern INPUT_NAME_PATTERN = Pattern.compile("(?is)\\bname\\s*=\\s*['\"]([^'\"]+)['\"]");
    private static final Pattern JS_TYPE_EMAIL_PATTERN = Pattern.compile("type\\s*[:=]\\s*['\"]email['\"]", Pattern.CASE_INSENSITIVE);
    private static final Pattern JS_NAME_EMAIL_PATTERN = Pattern.compile(
            "(?:name|id|placeholder)\\s*[:=]\\s*['\"][^'\"]*e-?mail[^'\"]*['\"]", Pattern.CASE_INSENSITIVE);
    private static final Pattern JS_EMAIL_KEY_PATTERN = Pattern.compile("['\"]e-?mail['\"]\\s*:", Pattern.CASE_INSENSITIVE);
    private static final Pattern JS_APPEND_EMAIL_PATTERN = Pattern.compile(
            "(?:append|set)\\s*\\(\\s*['\"][^'\"]*e-?mail[^'\"]*['\"]", Pattern.CASE_INSENSITIVE);
    private static final Pattern JS_CONTACT_URL_PATTERN = Pattern.compile(
            "['\"](/[^'\"\\s]{0,120}(?:newsletter|subscribe|contact[-_]?us|mailing-list|mailchimp|klaviyo)[^'\"\\s]{0,80})['\"]",
            Pattern.CASE_INSENSITIVE);

    private static final class ChatTurn {
        final String role;
        final String text;

        ChatTurn(String role, String text) {
            this.role = role;
            this.text = text;
        }
    }

    private static final class EmailTrafficAcc {
        final LinkedHashSet<String> nonAuth = new LinkedHashSet<>();
        final LinkedHashSet<String> authRelated = new LinkedHashSet<>();
        final LinkedHashSet<String> htmlNoEmail = new LinkedHashSet<>();
        final LinkedHashSet<String> jsScanned = new LinkedHashSet<>();
        final LinkedHashSet<String> queryMatches = new LinkedHashSet<>();
        final LinkedHashSet<String> termSnippets = new LinkedHashSet<>();
        int jsFiles;
        int siteMapItems;
        int siteMapInScope;
        int bodyDeepScans;
    }
	 private AtomicInteger completedTasksCounter = new AtomicInteger(0);


	 private JTextField retriesField;
	 private JTextField retryDelayField;
	 private JTextField maxChunkSizeField;
	 private JTextField rateLimitCountField;
	 private JTextField rateLimitWindowField;
	 private JTextField batchSizeField;

    /** When AI Model = Default, resolved provider/model per provider (updated on load/save). */
    private JTextField defaultOpenaiModelField;
    private JTextField defaultGeminiModelField;
    private JTextField defaultClaudeModelField;
    private JTextField defaultOpenrouterModelField;
    private JTextField defaultXaiModelField;
    /** Editable combo: presets plus ids from {@code GET /v1/models} after Validate or Get Latest Models. */
    private JComboBox<String> defaultLocalModelCombo;
    private String cachedDefaultOpenai = "openai/gpt-4o-mini";
    private String cachedDefaultGemini = "gemini/gemini-2.0-flash-lite";
    private String cachedDefaultClaude = "claude/claude-3-5-haiku-latest";
    private String cachedDefaultOpenrouter = "openrouter/mistralai/mistral-7b-instruct";
    private String cachedDefaultXai = "xai/grok-4-1-fast-non-reasoning";
    private String cachedDefaultLocal = "local/gemma4:e4b";
    /** Last {@code id} values from local {@code GET /v1/models} (empty until Validate / Get Latest Models). */
    private volatile List<String> cachedLocalModelIdsFromServer = new ArrayList<>();

    private JCheckBox passiveAiOnScannerIssuesCheckbox;
    private JCheckBox passiveAiAllTrafficCheckbox;
    private JCheckBox proxyBrowserLocalAiCheckbox;
    private JCheckBox proxyIncludeRepeaterCheckbox;
    private JCheckBox passiveAiInScopeCheckbox;
    private JTextField passiveMaxBodyKbField;
    /** When true, queue LLM audit only when Burp reports a Scanner issue (not from this extension). */
    private volatile boolean passiveAiOnScannerIssues = true;
    /** When true, also queue on every qualifying passive scan hit (high token use). */
    private volatile boolean passiveAiAuditAllTraffic = false;
    /** Proxy-originated browser traffic → LLM when local model is configured. */
    private volatile boolean proxyBrowserLocalAiEnabled = true;
    /** When true, also treat Repeater responses like Proxy for auto-audit (same local-model rules). */
    private volatile boolean proxyIncludeRepeater = false;
    private volatile boolean passiveAiInScopeOnly = true;
    private volatile int passiveMaxResponseBytes = DEFAULT_PASSIVE_MAX_BODY_KB * 1024;
    private final Set<String> passiveAuditDedupKeys = ConcurrentHashMap.newKeySet();
    private final Set<String> proxyBrowserAiDedupKeys = ConcurrentHashMap.newKeySet();
    private final AtomicInteger proxyAiWindowCount = new AtomicInteger();
    private volatile long proxyAiWindowStartMs = 0L;
    private static final int PROXY_AI_MAX_PER_WINDOW = 3;
    private static final long PROXY_AI_WINDOW_MS = 2500L;
    private final Map<String, ActiveHostRequestBudget> activeHostRequestBudgets = new ConcurrentHashMap<>();
    private volatile long lastActiveNullServiceLogMs = 0L;

    private static final class PendingScannerIssueBatch {
        final List<AuditIssue> issues = new ArrayList<>();
        volatile HttpRequestResponse representativeRr;
        volatile ScheduledFuture<?> scheduledFlush;
    }

    private static final class PremiumVerificationContext {
        final String model;
        final String apiKey;

        PremiumVerificationContext(String model, String apiKey) {
            this.model = model;
            this.apiKey = apiKey;
        }
    }

    private static final class PremiumVerificationResult {
        final boolean verified;
        final AuditIssueSeverity severity;
        final AuditIssueConfidence confidence;
        final String reason;

        PremiumVerificationResult(boolean verified, AuditIssueSeverity severity, AuditIssueConfidence confidence, String reason) {
            this.verified = verified;
            this.severity = severity;
            this.confidence = confidence;
            this.reason = reason == null ? "" : reason.trim();
        }
    }

    private final ConcurrentHashMap<String, PendingScannerIssueBatch> pendingScannerIssueBatches = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scannerIssueDebounceScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ai-auditor-scanner-issue-debounce");
        t.setDaemon(true);
        return t;
    });
    private final ScheduledExecutorService dashboardHeartbeatScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ai-auditor-dashboard-heartbeat");
        t.setDaemon(true);
        return t;
    });

	private JRadioButton detailedLoggingRadio;
	private JRadioButton detailedOnelinerLoggingRadio;
	    private JRadioButton limitedLoggingRadio;
    private ButtonGroup loggingButtonGroup;
    private List<String> availableModels = new ArrayList<>();

	private LoggingLevel currentLoggingLevel = LoggingLevel.DETAILED_ONELINER; // Default logging level

	private enum LoggingLevel {
		DETAILED,
		DETAILED_ONELINER,
		LIMITED
	}

	private enum LogCategory {
		GENERAL, // For general extension messages (always logged)
		REQUEST_BODY,
		API_RESPONSE,
		AI_RESPONSE_FULL, // Full AI response JSON
		RAW_CONTENT, // Raw content before JSON extraction
		EXTRACTED_JSON,
		TOKEN_INFO // Estimated tokens, number of requests
	}


	private static final DateTimeFormatter LOG_TS_FMT = 
		DateTimeFormatter.ofPattern("uuuu-MM-dd HH:mm:ss")
						 .withZone(ZoneId.systemDefault());

	private void log(String message) {
		log(message, LogCategory.GENERAL);
	}

	private void log(String message, LogCategory category) {
		String ts = LOG_TS_FMT.format(Instant.now());
		String formattedMessage = String.format("[%s] %s", ts, message);

		switch (currentLoggingLevel) {
			case DETAILED:
				api.logging().logToOutput(formattedMessage);
				break;
			case DETAILED_ONELINER:
				//if (category == LogCategory.EXTRACTED_JSON || category == LogCategory.TOKEN_INFO || category == LogCategory.GENERAL) {
				if (category == LogCategory.TOKEN_INFO || category == LogCategory.GENERAL) {
					api.logging().logToOutput(formattedMessage);
				} else {
					// Truncate for oneliner
					String truncatedMessage = message.length() > 100 ? message.substring(0, 100) + "..." : message;
					api.logging().logToOutput(String.format("[%s] %s (oneliner)", ts, truncatedMessage));
				}
				break;
			case LIMITED:
				if (category == LogCategory.EXTRACTED_JSON || category == LogCategory.GENERAL || category == LogCategory.TOKEN_INFO) {
					api.logging().logToOutput(formattedMessage);
				}
				break;
		}
	}


		private void disableSslVerification() {
			try {
				// 1) Trust all certs
				TrustManager[] trustAll = new TrustManager[]{ new X509TrustManager() {
					public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
					public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
					public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
				}};

				SSLContext sc = SSLContext.getInstance("TLS");
				sc.init(null, trustAll, new java.security.SecureRandom());
				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

				// 2) Skip hostname checks
				HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
			}
			catch (Exception e) {
				api.logging().logToError("Failed to disable SSL verification: " + e.getMessage());
			}
		}
		

	private JPanel createTemplateButtonsPanel() {
			JPanel templatePanel = new JPanel(new GridLayout(2, 2, 5, 5)); // 2x2 grid with 5px gaps
			templatePanel.setBorder(BorderFactory.createTitledBorder("Prompt Templates (click to copy)"));

			String[] templateNames = {"1.AI Role (Context)", "2.Guidelines", "*3.Output Format", "4.Output Limits"};
			String[] templateContents = {
				// Template 1:
				"You are an expert web application security researcher focused on actionable, evidence-backed findings. " +
				"Analyze the provided HTTP request and response for OWASP Top 10 coverage and related high-value weaknesses.\n\n" +
				"COVERAGE CHECKLIST:\n" +
				"1. Injection classes: SQL/NoSQL/command/template/HTML injection, SSRF, request smuggling\n" +
				"2. XSS classes: reflected, stored, DOM-based\n" +
				"3. Broken access control: IDOR/object-level auth issues, function-level auth bypass, client-side-only controls\n" +
				"4. Auth/session weaknesses: username enumeration, weak logout invalidation, unverified email change flows\n" +
				"5. CSRF and method/verb tampering related bypasses\n" +
				"6. Security misconfiguration/signals: verbose errors, vulnerable software version disclosure\n" +
				"7. Session/cookie issues: missing Secure, missing/weak SameSite\n" +
				"8. Unrestricted file upload and input validation/filtering gaps\n" +
				"9. Missing rate limiting on login/forgot-password/registration/forms/API abuse paths\n" +
				"10. Open redirect and phishing-assisted redirect behavior\n" +
				"11. Exposed secrets/API keys and whether restrictions/scopes are missing\n" +
				"12. Dependency confusion indicators (package naming/registry trust controls) when supported by evidence\n\n",

				// Template 2:
				"ANALYSIS GUIDELINES:\n" +
				"- Prioritize issues likely to be missed by Nessus, Nuclei, and Burp Scanner\n" +
				"- Include OWASP Top 10 mapping in explanation where applicable\n" +
				"- Skip theoretical findings without request/response evidence or a concrete abuse path\n" +
				"- For each finding include specific evidence and practical validation steps\n" +
				"- If evidence is weak, downgrade confidence/severity instead of overstating impact\n\n" +

				"SEVERITY CRITERIA:\n" +
				"HIGH: Immediate exploitation impact (RCE, auth bypass, critical broken access control, command injection, insecure deserialization, account takeover)\n" +
				"MEDIUM: Significant exploitable risk with meaningful impact (including reflected XSS when evidenced, stored XSS, IDOR with scoped impact, CSRF on sensitive actions, unrestricted upload with realistic abuse)\n" +
				"LOW: Real but limited-impact weakness (non-sensitive verbose errors, weak hardening with constrained exploitability)\n" +
				"INFORMATION: Useful security observations that need more evidence (possible endpoints/surfaces, weak signals only)\n\n" +

				"CONFIDENCE CRITERIA:\n" +
				"CERTAIN: Over 95 percent confident with clear evidence and reproducible\n" +
				"FIRM: Over 60 percent confident with very strong indicators but needing additional validation\n" +
				"TENTATIVE: At least 50 percent confident with indicators warranting further investigation\n\n",
					 
					 
				// Template 3
				"Format findings as JSON with the following structure:\n" +
					"{\n" +
					"  \"findings\": [{\n" +
					"    \"vulnerability\": \"Clear, specific, concise title of issue\",\n" +
					"    \"location\": \"Exact location in request/response (parameter, header, or path)\",\n" +
					"    \"explanation\": \"Detailed technical explanation with evidence from the request/response\",\n" +
					"    \"exploitation\": \"Specific steps to reproduce/exploit\",\n" +
					"    \"validation_steps\": \"Steps to validate the finding\",\n" +
					"    \"severity\": \"HIGH|MEDIUM|LOW|INFORMATION\",\n" +
					"    \"confidence\": \"CERTAIN|FIRM|TENTATIVE\"\n" +
					"  }]\n" +
					"}\n",
					
					
				// Template 4
				"IMPORTANT:\n" +
				"- Only report findings with clear evidence in the request/response\n" +
				"- Issues below 50 percent confidence should not be reported unless severity is HIGH\n" +
				"- Treat reflected XSS as at least MEDIUM when evidence is present (do not classify reflected XSS as LOW)\n" +
				"- Include specific paths, parameters, headers, and behavioral differences that indicate the vulnerability\n" +
				"- Explicitly check: username enumeration, CSRF + verb tampering, session invalidation on logout, unverified email change, open redirects, file upload controls, rate limiting, cookie Secure/SameSite, broken access control, request smuggling\n" +
				"- Mask sensitive values in output: never print full PAN/credit card, SSN/SIN, auth tokens, session IDs, API keys, or secrets (redact to partial form)\n" +
				"- For sensitive info disclosure, identify where evidence appears while keeping values redacted\n" +
				"- Only return JSON with findings, no other content!"


			};

			for (int i = 0; i < templateNames.length; i++) {
				JButton button = new JButton(templateNames[i]);
				final String contentToCopy = templateContents[i];
				button.addActionListener(e -> {
					try {
						StringSelection stringSelection = new StringSelection(contentToCopy);
						Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
						clipboard.setContents(stringSelection, null);
						log("'" + ((JButton)e.getSource()).getText() + "' content copied to clipboard.", LogCategory.GENERAL);
					} catch (Exception ex) {
						api.logging().logToError("Could not copy template to clipboard: " + ex.getMessage());
					}
				});
				templatePanel.add(button);
			}

			return templatePanel;
		}
		
     // Model Constants
    private static final Map<String, String> MODEL_MAPPING = new HashMap<>();
    
    @Override
    public void initialize(MontoyaApi api) {



		disableSslVerification();

        this.api = api;
        this.threadPoolManager = new ThreadPoolManager(api);    
        try {
            this.collaboratorClient = api.collaborator().createClient();
            log("Collaborator client initialized for active OOB checks.", LogCategory.GENERAL);
        } catch (Exception e) {
            this.collaboratorClient = null;
            api.logging().logToError("Collaborator client unavailable: " + e.getMessage());
        }
        log("Extension initializing...", LogCategory.GENERAL);

        // Test preferences
        try {
            String testKey = "test_" + System.currentTimeMillis();
            api.persistence().preferences().setString(PREF_PREFIX + "test", testKey);
            String retrieved = api.persistence().preferences().getString(PREF_PREFIX + "test");
            log("Preferences test: " + (testKey.equals(retrieved) ? "PASSED" : "FAILED"), LogCategory.GENERAL);
        } catch (Exception e) {
            api.logging().logToError("Preferences test error: " + e.getMessage());
        }
        
        // Register extension capabilities
        api.extension().setName(EXTENSION_NAME);
        migratePassiveAiPreferencesIfNeeded();
        migrateDualModelPreferencesIfNeeded();
        syncPassiveAiFlagsFromPreferences();
        migrateProxyBrowserLocalAiPreferenceIfNeeded();
        syncProxyBrowserLocalAiFlagFromPreferences();
        menuRegistration = api.userInterface().registerContextMenuItemsProvider(this);
        scanCheckRegistration = api.scanner().registerScanCheck(this);
        auditIssueHandlerRegistration = api.scanner().registerAuditIssueHandler(this::onNewScannerIssueForAiAudit);
        httpHandlerRegistration = api.http().registerHttpHandler(this);
        
        // Initialize UI and load settings
        SwingUtilities.invokeLater(() -> {
            log("Creating main tab...", LogCategory.GENERAL);
            createMainTab();
            
            // Add a small delay before loading settings to ensure UI is ready
            javax.swing.Timer swingTimer = new javax.swing.Timer(500, e -> {
                log("Loading saved settings...", LogCategory.GENERAL);
                loadSavedSettings();
				RequestChunker.setMaxTokensPerChunk(this.maxChunkSize);


                ((javax.swing.Timer)e.getSource()).stop();
            });
            swingTimer.setRepeats(false);
            swingTimer.start();
        });
        
        log("Extension initialization complete", LogCategory.GENERAL);
    }
    private void cleanup() {
        isShuttingDown = true;
        if (threadPoolManager != null) {
            threadPoolManager.shutdown();
        }
        if (menuRegistration != null) {
            menuRegistration.deregister();
        }
        if (scanCheckRegistration != null) {
            scanCheckRegistration.deregister();
        }
        if (auditIssueHandlerRegistration != null) {
            auditIssueHandlerRegistration.deregister();
        }
        if (httpHandlerRegistration != null) {
            httpHandlerRegistration.deregister();
        }
        scannerIssueDebounceScheduler.shutdown();
        try {
            if (!scannerIssueDebounceScheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                scannerIssueDebounceScheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scannerIssueDebounceScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        dashboardHeartbeatScheduler.shutdown();
        try {
            if (!dashboardHeartbeatScheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                dashboardHeartbeatScheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            dashboardHeartbeatScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

private void createMainTab() {
        mainPanel = new JPanel(new BorderLayout(0, 0));

        suiteTabs = new JTabbedPane();
        suiteTabs.addTab("Dashboard", buildDashboardPanel());
        suiteTabs.addTab("Chat", buildChatPanel());
        suiteTabs.addTab("Connect", wrapTabScroll(buildSetupProvidersPanel()));
        suiteTabs.addTab("Automation", wrapTabScroll(buildAutomationDefaultsPanel()));
        suiteTabs.addTab("Prompts", wrapTabScroll(buildPromptsPanel()));
        suiteTabs.addTab("Tuning", wrapTabScroll(buildAdvancedStatusPanel()));
        suiteTabs.setToolTipTextAt(0, "Live queue and activity for scans, PoCs, and Chat.");
        suiteTabs.setToolTipTextAt(1, "Ask the local LLM about captured traffic. Ctrl/Cmd+Enter to send.");
        suiteTabs.setToolTipTextAt(2, "API keys, local LLM URL, and model selection.");
        suiteTabs.setToolTipTextAt(3, "When to run the cheap/local bulk model automatically.");
        suiteTabs.setToolTipTextAt(4, "Scan, Explain, and PoC prompt text.");
        suiteTabs.setToolTipTextAt(5, "Retries, rate limits, batch size, and logging.");

        JPanel footer = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        footer.setBorder(BorderFactory.createEmptyBorder(2, 6, 6, 6));
        saveButton = new JButton("Save Settings");
        saveButton.setToolTipText("Saves keys, models, prompts, automation, and tuning.");
        saveButton.addActionListener(e -> saveSettings());
        footer.add(saveButton);
        JLabel saveHint = new JLabel("Connect · Automation · Prompts · Tuning");
        Color muted = UIManager.getColor("Label.disabledForeground");
        if (muted != null) {
            saveHint.setForeground(muted);
        }
        footer.add(saveHint);
        footer.setVisible(false);
        suiteTabs.addChangeListener(e -> {
            int i = suiteTabs.getSelectedIndex();
            footer.setVisible(i >= 2);
        });

        mainPanel.add(suiteTabs, BorderLayout.CENTER);
        mainPanel.add(footer, BorderLayout.SOUTH);

        new javax.swing.Timer(1000, e -> updateStatusPanel()).start();

        api.userInterface().registerSuiteTab("AI Auditor", mainPanel);
    }

    private JScrollPane wrapTabScroll(JPanel content) {
        JScrollPane sp = new JScrollPane(content);
        sp.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        sp.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        sp.getVerticalScrollBar().setUnitIncrement(16);
        return sp;
    }

    private JTextArea hintArea(String text, int rows) {
        JTextArea area = new JTextArea(text, rows, 40);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setOpaque(false);
        area.setBorder(null);
        Color muted = UIManager.getColor("Label.disabledForeground");
        if (muted != null) {
            area.setForeground(muted);
        }
        return area;
    }

    private void styleLogArea(JTextArea area, boolean wrapWords) {
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(wrapWords);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        Color bg = UIManager.getColor("TextArea.background");
        Color fg = UIManager.getColor("TextArea.foreground");
        if (bg != null) {
            area.setBackground(bg);
        }
        if (fg != null) {
            area.setForeground(fg);
            area.setCaretColor(fg);
        }
    }

    private JPanel collapsibleSection(String title, JComponent body, boolean startOpen) {
        JPanel wrap = new JPanel(new BorderLayout(0, 4));
        JButton toggle = new JButton();
        toggle.setFocusPainted(false);
        toggle.setHorizontalAlignment(SwingConstants.LEFT);
        body.setVisible(startOpen);
        toggle.setText((startOpen ? "▼ " : "▶ ") + title);
        toggle.addActionListener(e -> {
            boolean open = !body.isVisible();
            body.setVisible(open);
            toggle.setText((open ? "▼ " : "▶ ") + title);
            wrap.revalidate();
            wrap.repaint();
            Container parent = wrap.getParent();
            if (parent != null) {
                parent.revalidate();
                parent.repaint();
            }
        });
        wrap.add(toggle, BorderLayout.NORTH);
        wrap.add(body, BorderLayout.CENTER);
        return wrap;
    }

    private void addGridBagFiller(JPanel panel, GridBagConstraints gbc, int row) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(Box.createGlue(), gbc);
        gbc.weighty = 0;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 1;
    }

    private JPanel buildSetupProvidersPanel() {
        JPanel root = new JPanel(new GridBagLayout());
        GridBagConstraints rgbc = new GridBagConstraints();
        rgbc.insets = new Insets(6, 6, 6, 6);
        rgbc.fill = GridBagConstraints.HORIZONTAL;
        rgbc.gridx = 0;
        rgbc.weightx = 1.0;
        rgbc.gridwidth = GridBagConstraints.REMAINDER;

        JTextArea connectHint = hintArea(
                "Add a cloud API key or a Local LLM URL, click Validate, pick automatic/bulk and premium models, "
                        + "set Local LLM model id for local/…, then Save.",
                2);
        rgbc.gridy = 0;
        root.add(connectHint, rgbc);

        cloudApiValidationStatusLabel = new JLabel(" ");
        cloudApiValidationStatusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        rgbc.gridy = 1;
        root.add(cloudApiValidationStatusLabel, rgbc);

        JPanel cred = new JPanel(new GridBagLayout());
        cred.setBorder(BorderFactory.createTitledBorder("API keys and local server"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;
        addApiKeyField(cred, gbc, row++, "OpenAI API Key:", openaiKeyField = new JPasswordField(40), "openai");

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        cred.add(new JLabel("Google API Keys (one per line):"), gbc);
        geminiKeyField = new JTextArea(3, 40);
        geminiKeyField.setLineWrap(true);
        geminiKeyField.setWrapStyleWord(true);
        JScrollPane geminiKeyScrollPane = new JScrollPane(geminiKeyField);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        cred.add(geminiKeyScrollPane, gbc);
        JButton validateGeminiButton = new JButton("Validate");
        validateGeminiButton.addActionListener(e -> validateApiKey("gemini"));
        gbc.gridx = 2;
        gbc.weightx = 0;
        cred.add(validateGeminiButton, gbc);
        row++;

        addApiKeyField(cred, gbc, row++, "Anthropic API Key:", claudeKeyField = new JPasswordField(40), "claude");
        addApiKeyField(cred, gbc, row++, "OpenRouter API Key:", openrouterKeyField = new JPasswordField(40), "openrouter");
        addApiKeyField(cred, gbc, row++, "xAI (Grok) API Key:", xaiKeyField = new JPasswordField(40), "xai");

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        JLabel localEndpointLabel = new JLabel("Local LLM URL (LM Studio):");
        localEndpointLabel.setToolTipText("LM Studio → Local Server → copy OpenAI base URL (e.g. http://127.0.0.1:1234/v1). "
                + "Load Gemma 4 (or another chat) GGUF in LM Studio before starting the server.");
        cred.add(localEndpointLabel, gbc);
        localEndpointField = new JTextField(40);
        localEndpointField.setToolTipText(localEndpointLabel.getToolTipText());
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        cred.add(localEndpointField, gbc);
        JButton validateLocalUrlButton = new JButton("Validate");
        validateLocalUrlButton.setToolTipText("GET /v1/models on this base URL (uses optional API key below if set).");
        validateLocalUrlButton.addActionListener(e -> validateLocalLlmEndpoint());
        gbc.gridx = 2;
        gbc.weightx = 0;
        cred.add(validateLocalUrlButton, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 3;
        gbc.weightx = 1.0;
        localLlmValidationStatusLabel = new JLabel(" ");
        localLlmValidationStatusLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        cred.add(localLlmValidationStatusLabel, gbc);
        gbc.gridwidth = 1;
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        gbc.gridwidth = 1;
        cred.add(new JLabel("Local LLM API Key (if required):"), gbc);
        localKeyField = new JPasswordField(40);
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        cred.add(localKeyField, gbc);
        gbc.gridwidth = 1;
        row++;

        rgbc.gridy = 2;
        root.add(cred, rgbc);

        JPanel models = new JPanel(new GridBagLayout());
        models.setBorder(BorderFactory.createTitledBorder("Models"));
        gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        row = 0;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        JLabel autoModelLabel = new JLabel("Automatic / bulk model:");
        autoModelLabel.setToolTipText("Used for automatic, high-volume work: Scanner-issue follow-ups, Proxy/Repeater capture, "
                + "and passive “all traffic”. Choose local/… for on-prem inference or a small cheap cloud model. "
                + "When using local/…, set “Local LLM model id” below to the server’s OpenAI JSON model name.");
        models.add(autoModelLabel, gbc);
        automaticAuditModelDropdown = new JComboBox<>();
        automaticAuditModelDropdown.setToolTipText(autoModelLabel.getToolTipText());
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        models.add(automaticAuditModelDropdown, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        JLabel defaultLocalLabel = new JLabel("Local LLM model id:");
        defaultLocalModelCombo = new JComboBox<>(LOCAL_LLM_MODEL_ID_PRESETS);
        defaultLocalModelCombo.setEditable(true);
        defaultLocalModelCombo.setPrototypeDisplayValue("gemma4:26b-instruct-128k");
        defaultLocalModelCombo.setToolTipText("Pick a tag from the list (filled from GET /v1/models after you Validate the Local LLM URL or click Get Latest Models), or type any id. "
                + "Sent as JSON \"model\" for every local/… request. Ollama: same as `ollama list`. LM Studio: Local Server model id.");
        defaultLocalLabel.setToolTipText(defaultLocalModelCombo.getToolTipText());
        models.add(defaultLocalLabel, gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        models.add(defaultLocalModelCombo, gbc);
        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        JLabel manualModelLabel = new JLabel("Premium Model for PoCs:");
        manualModelLabel.setToolTipText("Used when you start an action: context menu scans, Explain me this, PoC / exploitation notes, "
                + "and similar. Pick a stronger model when quality matters.");
        models.add(manualModelLabel, gbc);
        manualInvestigationModelDropdown = new JComboBox<>();
        manualInvestigationModelDropdown.setToolTipText(manualModelLabel.getToolTipText());
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        models.add(manualInvestigationModelDropdown, gbc);
        row++;

        resetModelsToDefault();

        JPanel modelButtonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton resetButton = new JButton("Reset to Default");
        resetButton.addActionListener(e -> resetModelsToDefault());
        modelButtonsPanel.add(resetButton);
        JButton fetchButton = new JButton("Get Latest Models");
        fetchButton.addActionListener(e -> fetchLatestModels());
        modelButtonsPanel.add(fetchButton);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        gbc.weightx = 0;
        models.add(new JLabel("Filter list (comma = hide names containing):"), gbc);
        filterModelsField = new JTextField(40);
        filterModelsField.setToolTipText("Example: embed, image, vision — hides matching entries from the dropdown lists.");
        filterModelsField.addKeyListener(new KeyAdapter() {
            public void keyReleased(KeyEvent e) {
                applyModelFilter();
            }
        });
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        models.add(filterModelsField, gbc);

        gbc.gridx = 1;
        gbc.gridy = ++row;
        models.add(modelButtonsPanel, gbc);

        rgbc.gridy = 3;
        root.add(models, rgbc);

        GridBagConstraints filler = new GridBagConstraints();
        filler.gridx = 0;
        filler.gridy = 4;
        filler.weighty = 1.0;
        filler.weightx = 1.0;
        filler.fill = GridBagConstraints.BOTH;
        filler.gridwidth = GridBagConstraints.REMAINDER;
        root.add(Box.createGlue(), filler);
        return root;
    }

    private JPanel buildAutomationDefaultsPanel() {
        JPanel root = new JPanel(new GridBagLayout());
        GridBagConstraints rgbc = new GridBagConstraints();
        rgbc.insets = new Insets(6, 6, 6, 6);
        rgbc.fill = GridBagConstraints.HORIZONTAL;
        rgbc.gridx = 0;
        rgbc.weightx = 1.0;
        rgbc.gridwidth = GridBagConstraints.REMAINDER;

        JTextArea bgHint = hintArea(
                "High-volume automatic audits. On Connect, pick the automatic/bulk model (prefer local/…) and Local LLM model id. "
                        + "Premium PoC is for right-click / Explain only — not these checkboxes.",
                2);
        rgbc.gridy = 0;
        root.add(bgHint, rgbc);

        JPanel autoBox = new JPanel(new GridBagLayout());
        autoBox.setBorder(BorderFactory.createTitledBorder("When to run the cheap / local bulk model without you clicking"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.gridx = 0;
        int row = 0;

        passiveAiOnScannerIssuesCheckbox = new JCheckBox("After Scanner issues, queue a bulk-model review");
        passiveAiOnScannerIssuesCheckbox.setSelected(passiveAiOnScannerIssues);
        passiveAiOnScannerIssuesCheckbox.setToolTipText("Uses the Connect automatic/bulk model only. Prefer local or a small cloud model — each Scanner issue can trigger another API call.");
        passiveAiAllTrafficCheckbox = new JCheckBox("All passively scanned HTTP (high volume; not Proxy-only)");
        passiveAiAllTrafficCheckbox.setSelected(passiveAiAuditAllTraffic);
        passiveAiAllTrafficCheckbox.setToolTipText("Burp passive Scan check: runs the automatic/bulk model on most HTTP Burp passively analyzes (sitemap / crawl scale — high volume). "
                + "This is not limited to traffic through the Proxy tool. Prefer local or a cheap cloud bulk model.");
        proxyBrowserLocalAiCheckbox = new JCheckBox("Proxied traffic only (Proxy ± Repeater)");
        proxyBrowserLocalAiCheckbox.setSelected(proxyBrowserLocalAiEnabled);
        proxyBrowserLocalAiCheckbox.setToolTipText(PROXY_BROWSER_LOCAL_AI_TOOLTIP
                + " Skips JavaScript/CSS. Rate-limited so a busy site cannot freeze Burp.");
        proxyIncludeRepeaterCheckbox = new JCheckBox("Include Repeater with proxied-only audits");
        proxyIncludeRepeaterCheckbox.setSelected(proxyIncludeRepeater);
        proxyIncludeRepeaterCheckbox.setToolTipText("When enabled, Repeater responses use the same proxied-only bulk path and local/… + URL rules as the Proxy checkbox above.");
        passiveAiInScopeCheckbox = new JCheckBox("In-scope URLs only");
        passiveAiInScopeCheckbox.setSelected(passiveAiInScopeOnly);

        gbc.gridy = row++;
        autoBox.add(passiveAiOnScannerIssuesCheckbox, gbc);
        gbc.gridy = row++;
        autoBox.add(passiveAiAllTrafficCheckbox, gbc);
        gbc.gridy = row++;
        autoBox.add(proxyBrowserLocalAiCheckbox, gbc);
        gbc.gridy = row++;
        autoBox.add(proxyIncludeRepeaterCheckbox, gbc);
        gbc.gridy = row++;
        autoBox.add(passiveAiInScopeCheckbox, gbc);

        passiveAiOnScannerIssuesCheckbox.addItemListener(e -> {
            boolean on = e.getStateChange() == ItemEvent.SELECTED;
            passiveAiOnScannerIssues = on;
            api.persistence().preferences().setBoolean(PREF_PREFIX + "passive_ai_scanner_issues", on);
        });
        passiveAiAllTrafficCheckbox.addItemListener(e -> {
            boolean on = e.getStateChange() == ItemEvent.SELECTED;
            passiveAiAuditAllTraffic = on;
            api.persistence().preferences().setBoolean(PREF_PREFIX + "passive_ai_all_traffic", on);
        });
        proxyBrowserLocalAiCheckbox.addItemListener(e -> {
            boolean on = e.getStateChange() == ItemEvent.SELECTED;
            proxyBrowserLocalAiEnabled = on;
            api.persistence().preferences().setBoolean(PREF_PREFIX + "proxy_browser_local_ai", on);
        });
        proxyIncludeRepeaterCheckbox.addItemListener(e -> {
            boolean on = e.getStateChange() == ItemEvent.SELECTED;
            proxyIncludeRepeater = on;
            api.persistence().preferences().setBoolean(PREF_PREFIX + "proxy_include_repeater", on);
        });
        passiveAiInScopeCheckbox.addItemListener(e -> {
            boolean on = e.getStateChange() == ItemEvent.SELECTED;
            passiveAiInScopeOnly = on;
            api.persistence().preferences().setBoolean(PREF_PREFIX + "passive_ai_in_scope", on);
        });

        rgbc.gridy = 1;
        root.add(autoBox, rgbc);

        JTextArea proxySetupGuideArea = new JTextArea(LOCAL_LM_STUDIO_SETUP_TEXT, 12, 52);
        proxySetupGuideArea.setEditable(false);
        proxySetupGuideArea.setLineWrap(true);
        proxySetupGuideArea.setWrapStyleWord(true);
        proxySetupGuideArea.setBackground(UIManager.getColor("Panel.background"));
        proxySetupGuideArea.setToolTipText("Ollama: gemma4:e4b by default; gemma4:26b if you have the RAM. Or use LM Studio steps below.");
        JScrollPane guideScroll = new JScrollPane(proxySetupGuideArea);
        guideScroll.setPreferredSize(new Dimension(520, 180));
        rgbc.gridy = 2;
        root.add(collapsibleSection("Local LLM setup (Ollama or LM Studio)", guideScroll, false), rgbc);

        JPanel limits = new JPanel(new GridBagLayout());
        limits.setBorder(BorderFactory.createTitledBorder("Limits, proxy, and cloud \"Default\" model IDs"));
        gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        row = 0;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        gbc.gridwidth = 1;
        limits.add(new JLabel("Max passive response size (KB):"), gbc);
        passiveMaxBodyKbField = new JTextField(String.valueOf(DEFAULT_PASSIVE_MAX_BODY_KB), 8);
        passiveMaxBodyKbField.setToolTipText("Larger responses are skipped for automatic passive audits.");
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        limits.add(passiveMaxBodyKbField, gbc);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        gbc.weightx = 0;
        JLabel proxyLabel = new JLabel("HTTP proxy for cloud APIs only (host:port):");
        proxyLabel.setToolTipText("Optional. Localhost and your Local LLM host stay direct (not via this proxy).");
        limits.add(proxyLabel, gbc);
        proxyField = new JTextField(24);
        proxyField.setToolTipText("Optional HTTP proxy for this extension’s outbound API calls (OpenAI, Gemini, etc.). "
                + "Traffic to localhost, 127.0.0.1, and your Local LLM Endpoint host is sent direct "
                + "so LM Studio still works when Burp uses a separate upstream proxy for browsing.");
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        limits.add(proxyField, gbc);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        limits.add(new JLabel("If a model dropdown says Default, the extension uses these cloud default IDs:"), gbc);
        gbc.gridwidth = 1;

        defaultOpenaiModelField = new JTextField("gpt-4o-mini", 24);
        defaultGeminiModelField = new JTextField("gemini-2.0-flash-lite", 24);
        defaultClaudeModelField = new JTextField("claude-3-5-haiku-latest", 24);
        defaultOpenrouterModelField = new JTextField("mistralai/mistral-7b-instruct", 24);
        defaultXaiModelField = new JTextField("grok-4-1-fast-non-reasoning", 24);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        gbc.weightx = 0;
        limits.add(new JLabel("OpenAI:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        limits.add(defaultOpenaiModelField, gbc);
        gbc.gridx = 0;
        gbc.gridy = ++row;
        gbc.weightx = 0;
        limits.add(new JLabel("Gemini:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        limits.add(defaultGeminiModelField, gbc);
        gbc.gridx = 0;
        gbc.gridy = ++row;
        limits.add(new JLabel("Claude:"), gbc);
        gbc.gridx = 1;
        limits.add(defaultClaudeModelField, gbc);
        gbc.gridx = 0;
        gbc.gridy = ++row;
        limits.add(new JLabel("OpenRouter:"), gbc);
        gbc.gridx = 1;
        limits.add(defaultOpenrouterModelField, gbc);
        gbc.gridx = 0;
        gbc.gridy = ++row;
        limits.add(new JLabel("xAI:"), gbc);
        gbc.gridx = 1;
        limits.add(defaultXaiModelField, gbc);

        rgbc.gridy = 3;
        root.add(limits, rgbc);

        GridBagConstraints filler = new GridBagConstraints();
        filler.gridx = 0;
        filler.gridy = 4;
        filler.weighty = 1.0;
        filler.weightx = 1.0;
        filler.fill = GridBagConstraints.BOTH;
        filler.gridwidth = GridBagConstraints.REMAINDER;
        root.add(Box.createGlue(), filler);
        return root;
    }

    private JPanel buildPromptsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        panel.add(hintArea("The main prompt is pre-filled with the default scan instructions. "
                + "Edit freely. Template buttons copy individual sections to the clipboard.", 2), gbc);

        gbc.gridy = ++row;
        panel.add(new JLabel("Main prompt (most scans use this)"), gbc);

        gbc.gridy = ++row;
        promptTemplateArea = new JTextArea(10, 50);
        promptTemplateArea.setLineWrap(true);
        promptTemplateArea.setWrapStyleWord(true);
        promptTemplateArea.setText(getDefaultPromptTemplate());
        panel.add(new JScrollPane(promptTemplateArea), gbc);

        gbc.gridy = ++row;
        JPanel templateButtonsPanel = createTemplateButtonsPanel();
        panel.add(templateButtonsPanel, gbc);

        gbc.gridy = ++row;
        panel.add(new JLabel("Explain Me This (right-click menu)"), gbc);
        explainMeThisPromptArea = new JTextArea(5, 50);
        explainMeThisPromptArea.setLineWrap(true);
        explainMeThisPromptArea.setWrapStyleWord(true);
        explainMeThisPromptArea.setText("Explain the following input from a security and penetration testing perspective as if you are a senior penetration tester - describe what it is, what it can do, and suggest possible checks or exploitation opportunities. Explain me briefly.");
        gbc.gridy = ++row;
        panel.add(new JScrollPane(explainMeThisPromptArea), gbc);

        gbc.gridy = ++row;
        panel.add(new JLabel("Investigate / PoC (proof-of-concept style)"), gbc);
        pocPromptArea = new JTextArea(6, 50);
        pocPromptArea.setLineWrap(true);
        pocPromptArea.setWrapStyleWord(true);
        pocPromptArea.setText(getDefaultPocPrompt());
        gbc.gridy = ++row;
        panel.add(new JScrollPane(pocPromptArea), gbc);

        gbc.gridwidth = 1;
        addGridBagFiller(panel, gbc, ++row);
        return panel;
    }

    private JPanel buildAdvancedStatusPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        int row = 0;
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        panel.add(hintArea("Optional. Open this if requests fail, hit rate limits, or logs are too noisy.", 1), gbc);
        gbc.gridwidth = 1;

        gbc.gridx = 0;
        gbc.gridy = ++row;
        panel.add(new JLabel("Max Retries:"), gbc);
        retriesField = new JTextField(20);
        retriesField.setText("3");
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(retriesField, gbc);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        gbc.weightx = 0;
        panel.add(new JLabel("Retry Delay (ms):"), gbc);
        retryDelayField = new JTextField(20);
        retryDelayField.setText("1000");
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(retryDelayField, gbc);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        gbc.weightx = 0;
        panel.add(new JLabel("Max token size:"), gbc);
        maxChunkSizeField = new JTextField(20);
        maxChunkSizeField.setText("16384");
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        panel.add(maxChunkSizeField, gbc);

        JPanel tokenButtonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        String[] tokenSizes = {"16K", "64K", "100K", "1M"};
        for (String size : tokenSizes) {
            JButton button = new JButton(size);
            button.addActionListener(e -> {
                String value = size.replace("M", "000000").replace("K", "000");
                maxChunkSizeField.setText(value);
            });
            tokenButtonsPanel.add(button);
        }
        gbc.gridx = 1;
        gbc.gridy = ++row;
        panel.add(tokenButtonsPanel, gbc);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        panel.add(new JLabel("Rate Limit (requests):"), gbc);
        rateLimitCountField = new JTextField(20);
        rateLimitCountField.setText("50");
        gbc.gridx = 1;
        panel.add(rateLimitCountField, gbc);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        panel.add(new JLabel("Rate Window (sec):"), gbc);
        rateLimitWindowField = new JTextField(20);
        rateLimitWindowField.setText("60");
        gbc.gridx = 1;
        panel.add(rateLimitWindowField, gbc);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        panel.add(new JLabel("Batch Size:"), gbc);
        batchSizeField = new JTextField(20);
        batchSizeField.setText("5");
        gbc.gridx = 1;
        panel.add(batchSizeField, gbc);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        panel.add(new JLabel("Logging Level:"), gbc);

        JPanel loggingPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        detailedLoggingRadio = new JRadioButton("Detailed logging");
        detailedOnelinerLoggingRadio = new JRadioButton("Detailed (one line)");
        limitedLoggingRadio = new JRadioButton("Limited logging");
        loggingButtonGroup = new ButtonGroup();
        loggingButtonGroup.add(detailedLoggingRadio);
        loggingButtonGroup.add(detailedOnelinerLoggingRadio);
        loggingButtonGroup.add(limitedLoggingRadio);
        loggingPanel.add(detailedLoggingRadio);
        loggingPanel.add(detailedOnelinerLoggingRadio);
        loggingPanel.add(limitedLoggingRadio);

        gbc.gridy = ++row;
        panel.add(loggingPanel, gbc);
        gbc.gridwidth = 1;

        detailedLoggingRadio.addActionListener(e -> currentLoggingLevel = LoggingLevel.DETAILED);
        detailedOnelinerLoggingRadio.addActionListener(e -> currentLoggingLevel = LoggingLevel.DETAILED_ONELINER);
        limitedLoggingRadio.addActionListener(e -> currentLoggingLevel = LoggingLevel.LIMITED);

        JButton testGeminiCyclingButton = new JButton("Test Gemini Key Cycling");
        testGeminiCyclingButton.addActionListener(e -> testGeminiKeyCycling());
        gbc.gridy = ++row;
        panel.add(testGeminiCyclingButton, gbc);
        gbc.gridwidth = 1;

        addGridBagFiller(panel, gbc, ++row);
        return panel;
    }

    /**
     * Task queue + activity feed for AI Auditor work.
     */
    private JPanel buildDashboardPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 24, 4));
        statusPanel.setBorder(BorderFactory.createTitledBorder("Queue"));
        activeTasksLabel = new JLabel("Active: 0");
        queuedTasksLabel = new JLabel("Queued: 0");
        completedTasksLabel = new JLabel("Completed: 0");
        for (JLabel label : new JLabel[]{activeTasksLabel, queuedTasksLabel, completedTasksLabel}) {
            label.setFont(label.getFont().deriveFont(Font.BOLD, 13f));
            statusPanel.add(label);
        }

        dashboardActivityArea = new JTextArea(18, 70);
        styleLogArea(dashboardActivityArea, false);
        dashboardActivityArea.setText("Ready. Activity appears here as you run scans, PoCs, and Chat.\n");
        JScrollPane activityScroll = new JScrollPane(dashboardActivityArea);
        activityScroll.setBorder(BorderFactory.createTitledBorder("Activity"));

        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton clearActivity = new JButton("Clear");
        clearActivity.addActionListener(e -> {
            dashboardActivityArea.setText("Ready. Activity appears here as you run scans, PoCs, and Chat.\n");
        });
        JButton copyLog = new JButton("Copy");
        copyLog.addActionListener(e -> copyActivityLogToClipboard());
        controls.add(clearActivity);
        controls.add(copyLog);

        panel.add(statusPanel, BorderLayout.NORTH);
        panel.add(activityScroll, BorderLayout.CENTER);
        panel.add(controls, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildChatPanel() {
        JPanel root = new JPanel(new BorderLayout(4, 4));
        root.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

        JPanel north = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(0, 2, 2, 2);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridy = 0;

        JLabel header = new JLabel("Ctrl/Cmd+Enter to send");
        header.setFont(header.getFont().deriveFont(Font.BOLD, 13f));
        gbc.gridx = 0;
        gbc.weightx = 0;
        north.add(header, gbc);

        chatStatusLabel = new JLabel("Ready — local LLM");
        Color muted = UIManager.getColor("Label.disabledForeground");
        if (muted != null) {
            chatStatusLabel.setForeground(muted);
        }
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        north.add(chatStatusLabel, gbc);

        chatIncludeHttpCheckbox = new JCheckBox("Include Burp traffic", true);
        chatIncludeHttpCheckbox.setToolTipText("Adds a digest of Proxy history and Site Map, plus any Send-to-Chat attachment. Leave on so Chat can search captured traffic instead of giving generic advice.");
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        north.add(chatIncludeHttpCheckbox, gbc);

        chatAttachmentLabel = new JLabel("No HTTP attached.");
        if (muted != null) {
            chatAttachmentLabel.setForeground(muted);
        }
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        north.add(chatAttachmentLabel, gbc);

        root.add(north, BorderLayout.NORTH);

        chatHistoryArea = new JTextArea(8, 70);
        styleLogArea(chatHistoryArea, true);
        refreshChatHistoryView();
        JScrollPane historyScroll = new JScrollPane(chatHistoryArea);
        historyScroll.setBorder(BorderFactory.createTitledBorder("Conversation"));
        root.add(historyScroll, BorderLayout.CENTER);

        JPanel south = new JPanel(new BorderLayout(4, 4));
        south.add(buildChatCheckBar(), BorderLayout.NORTH);

        chatInputArea = new JTextArea(2, 50);
        chatInputArea.setLineWrap(true);
        chatInputArea.setWrapStyleWord(true);
        chatInputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        chatInputArea.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_ENTER && (e.isControlDown() || e.isMetaDown())) {
                    e.consume();
                    sendChatPrompt();
                }
            }
        });
        JScrollPane inputScroll = new JScrollPane(chatInputArea);
        inputScroll.setBorder(BorderFactory.createTitledBorder("Prompt"));

        JPanel buttons = new JPanel(new GridLayout(3, 1, 0, 4));
        chatSendButton = new JButton("Send");
        chatSendButton.setToolTipText("Send to the local LLM (Ctrl/Cmd+Enter). Falls back to Premium Model for PoCs if no local URL is set.");
        chatSendButton.addActionListener(e -> sendChatPrompt());
        JButton clearChat = new JButton("Clear");
        clearChat.setToolTipText("Clear conversation");
        clearChat.addActionListener(e -> clearChatConversation(false));
        JButton clearAttach = new JButton("Detach");
        clearAttach.setToolTipText("Clear attached HTTP / issue context");
        clearAttach.addActionListener(e -> clearChatAttachment());
        buttons.add(chatSendButton);
        buttons.add(clearChat);
        buttons.add(clearAttach);
        buttons.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 0));
        JPanel promptRow = new JPanel(new BorderLayout(4, 0));
        promptRow.add(inputScroll, BorderLayout.CENTER);
        promptRow.add(buttons, BorderLayout.EAST);
        south.add(promptRow, BorderLayout.CENTER);

        root.add(south, BorderLayout.SOUTH);
        return root;
    }

    private JPanel buildChatCheckBar() {
        JPanel wrap = new JPanel(new BorderLayout(0, 2));
        JLabel label = new JLabel("Checks");
        label.setToolTipText("Sends a focused hunt against the Site Map / Proxy digest. Turns Include Burp traffic on.");
        Color muted = UIManager.getColor("Label.disabledForeground");
        if (muted != null) {
            label.setForeground(muted);
        }
        wrap.add(label, BorderLayout.WEST);
        JPanel row = new JPanel(new GridLayout(2, 3, 4, 4));
        chatCheckButtons.clear();
        for (String[] check : CHAT_VULN_CHECKS) {
            JButton button = new JButton(check[0]);
            button.setToolTipText(check[1]);
            final String prompt = check[1];
            button.addActionListener(e -> sendChatCheck(prompt));
            chatCheckButtons.add(button);
            row.add(button);
        }
        wrap.add(row, BorderLayout.CENTER);
        return wrap;
    }

    private void focusChatTab() {
        if (suiteTabs == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            if (suiteTabs == null) {
                return;
            }
            for (int i = 0; i < suiteTabs.getTabCount(); i++) {
                if ("Chat".equals(suiteTabs.getTitleAt(i))) {
                    suiteTabs.setSelectedIndex(i);
                    if (chatInputArea != null) {
                        chatInputArea.requestFocusInWindow();
                    }
                    return;
                }
            }
        });
    }

    private void refreshChatHistoryView() {
        if (chatHistoryArea == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Type a question below, use a Checks button, or attach traffic from a right-click menu.\n\n");
        for (ChatTurn turn : chatTurns) {
            sb.append("── ").append(turn.role).append(" ──\n");
            sb.append(turn.text).append("\n\n");
        }
        if (chatBusy) {
            sb.append("── Assistant ──\n(thinking…)\n\n");
        }
        chatHistoryArea.setText(sb.toString());
        chatHistoryArea.setCaretPosition(chatHistoryArea.getDocument().getLength());
    }

    private void setChatBusy(boolean busy) {
        chatBusy = busy;
        if (chatSendButton != null) {
            chatSendButton.setEnabled(!busy);
        }
        for (JButton button : chatCheckButtons) {
            button.setEnabled(!busy);
        }
        if (chatInputArea != null) {
            chatInputArea.setEnabled(!busy);
        }
        refreshChatHistoryView();
    }

    private void clearChatConversation(boolean keepAttachment) {
        chatTurns.clear();
        if (!keepAttachment) {
            clearChatAttachment();
        }
        setChatBusy(false);
        if (chatStatusLabel != null) {
            chatStatusLabel.setText("Conversation cleared. Defaults to the local LLM.");
        }
    }

    private void clearChatAttachment() {
        chatAttachedHttp = null;
        chatAttachedExtra = null;
        if (chatAttachmentLabel != null) {
            chatAttachmentLabel.setText("No HTTP attached.");
        }
        if (chatIncludeHttpCheckbox != null) {
            chatIncludeHttpCheckbox.setSelected(true);
        }
    }

    private void attachTrafficToChat(HttpRequestResponse rr, String extraContext) {
        chatAttachedHttp = rr;
        chatAttachedExtra = extraContext;
        String urlLabel = "HTTP request";
        try {
            if (rr != null && rr.request() != null && rr.request().url() != null) {
                urlLabel = rr.request().url();
            }
        } catch (Exception ignored) {
        }
        String extraNote = (extraContext != null && !extraContext.isEmpty())
                ? " + extra context (" + extraContext.length() + " chars)"
                : "";
        final String label = "Attached: " + truncateForIssueTitle(urlLabel, 90) + extraNote;
        SwingUtilities.invokeLater(() -> {
            if (chatAttachmentLabel != null) {
                chatAttachmentLabel.setText(label);
            }
            if (chatIncludeHttpCheckbox != null) {
                chatIncludeHttpCheckbox.setSelected(true);
            }
            focusChatTab();
        });
        appendDashboardActivity("Chat attachment — " + label);
        api.logging().raiseInfoEvent("AI Auditor: attached to Chat. Open AI Auditor → Chat and type a prompt.");
    }

    private void attachIssuesToChat(List<AuditIssue> issues) {
        if (issues == null || issues.isEmpty()) {
            return;
        }
        AuditIssue first = issues.get(0);
        List<HttpRequestResponse> traffic = resolveTrafficForIssue(first);
        HttpRequestResponse rr = (traffic != null && !traffic.isEmpty()) ? traffic.get(0) : null;
        StringBuilder extra = new StringBuilder();
        extra.append(issues.size() == 1 ? "=== Burp issue ===\n" : "=== Burp issues (" + issues.size() + ") ===\n");
        for (AuditIssue issue : issues) {
            extra.append("Name: ").append(issue.name()).append("\n");
            extra.append("Severity: ").append(issue.severity()).append("\n");
            extra.append("Confidence: ").append(issue.confidence()).append("\n");
            if (issue.detail() != null && !issue.detail().isEmpty()) {
                extra.append("Detail:\n").append(issue.detail()).append("\n");
            }
            extra.append("\n");
        }
        attachTrafficToChat(rr, extra.toString());
    }

    private String extractSelectedEditorText(MessageEditorHttpRequestResponse editor) {
        Optional<Range> selectionRange = editor.selectionOffsets();
        if (!selectionRange.isPresent()) {
            return null;
        }
        int start = selectionRange.get().startIndexInclusive();
        int end = selectionRange.get().endIndexExclusive();
        String editorContent = editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST
                ? editor.requestResponse().request().toString()
                : editor.requestResponse().response() != null ? editor.requestResponse().response().toString() : "";
        if (start >= 0 && end <= editorContent.length() && start < end) {
            return editorContent.substring(start, end);
        }
        return null;
    }

    private String buildChatPrompt(String currentQuestion, boolean includeTraffic) {
        StringBuilder sb = new StringBuilder();
        sb.append("You are a senior penetration tester sitting inside Burp Suite with the operator. ");
        sb.append("The EVIDENCE blocks below are captured Proxy history / Site Map (and any attached request). ");
        sb.append("Answer the operator's question from that evidence. ");
        sb.append("Do the analysis yourself: list concrete method, URL, and field/form names. ");
        sb.append("Never tell the operator to open HTTP History, filter traffic, crawl, or send items to Repeater ");
        sb.append("instead of answering. If evidence is empty or has no matches, say so and report the scan counts. ");
        sb.append("Do not invent endpoints that are not in the evidence. ");
        sb.append("Do not return JSON scanner findings unless the operator asks for that format.\n\n");

        if (includeTraffic) {
            sb.append(collectBurpTrafficDigest(currentQuestion)).append("\n\n");
            if (chatAttachedHttp != null && chatAttachedHttp.request() != null) {
                String traffic = "=== Attached HTTP request ===\n"
                        + chatAttachedHttp.request().toString()
                        + "\n\n=== Attached HTTP response ===\n"
                        + (chatAttachedHttp.response() != null ? chatAttachedHttp.response().toString() : "(no response captured)");
                sb.append(trimPocEvidenceForPrompt(traffic, "chat attachment")).append("\n\n");
            }
            if (chatAttachedExtra != null && !chatAttachedExtra.isEmpty()) {
                sb.append("=== Extra context (selected text or issue) ===\n");
                sb.append(truncateMiddleWithNotice(chatAttachedExtra, 20_000)).append("\n\n");
            }
        } else {
            sb.append("=== Evidence ===\n(Operator turned off Include Burp traffic. No Proxy history was attached.)\n\n");
        }

        int start = Math.max(0, chatTurns.size() - CHAT_HISTORY_MAX_TURNS);
        if (start < chatTurns.size()) {
            sb.append("=== Conversation so far ===\n");
            for (int i = start; i < chatTurns.size(); i++) {
                ChatTurn turn = chatTurns.get(i);
                sb.append(turn.role).append(":\n").append(turn.text).append("\n\n");
            }
        }

        sb.append("=== Current question ===\n").append(currentQuestion);
        if (sb.length() > CHAT_PROMPT_MAX_CHARS) {
            return truncateMiddleWithNotice(sb.toString(), CHAT_PROMPT_MAX_CHARS);
        }
        return sb.toString();
    }

    private String collectBurpTrafficDigest(String question) {
        EmailTrafficAcc acc = new EmailTrafficAcc();
        List<String> terms = extractSearchTerms(question);
        boolean wantEmail = questionLooksLikeEmailOrFormHunt(question, terms);
        boolean wantBodies = wantEmail || questionLooksLikeBodyHunt(question, terms);
        int proxyTotal = 0;
        int proxyConsidered = 0;
        boolean restrictedToScope = false;
        try {
            List<ProxyHttpRequestResponse> hist = api.proxy().history();
            proxyTotal = hist != null ? hist.size() : 0;
            long deadline = System.currentTimeMillis() + CHAT_SCAN_BUDGET_MS;
            LinkedHashSet<String> prefixes = new LinkedHashSet<>();
            if (hist != null && !hist.isEmpty()) {
                int peek = Math.min(hist.size(), 80);
                for (int i = hist.size() - 1; i >= hist.size() - peek; i--) {
                    try {
                        HttpRequest req = hist.get(i) != null ? hist.get(i).request() : null;
                        if (req != null && req.isInScope()) {
                            restrictedToScope = true;
                            break;
                        }
                    } catch (Exception ignored) {
                    }
                }
                int from = Math.max(0, hist.size() - CHAT_HISTORY_SCAN_MAX_ITEMS);
                for (int i = hist.size() - 1; i >= from; i--) {
                    if (System.currentTimeMillis() > deadline) {
                        break;
                    }
                    ProxyHttpRequestResponse item = hist.get(i);
                    if (item == null || item.request() == null) {
                        continue;
                    }
                    HttpRequest req = item.request();
                    if (restrictedToScope && !safeIsInScope(req)) {
                        continue;
                    }
                    if (prefixes.size() < 16) {
                        String prefix = originPrefix(req);
                        if (prefix != null) {
                            prefixes.add(prefix);
                        }
                    }
                    proxyConsidered++;
                    noteQueryMatch(acc, terms, req);
                    HttpResponse histRes = item.hasResponse() ? item.response() : null;
                    if (wantEmail) {
                        collectEmailEvidenceFromExchange(req, histRes, acc);
                    } else if (wantBodies) {
                        collectTermSnippetsFromExchange(req, histRes, terms, acc);
                    }
                }
            }

            List<HttpRequestResponse> map = loadFullSiteMap(prefixes);
            acc.siteMapItems = map.size();
            List<HttpRequestResponse> matchBodies = new ArrayList<>();
            List<HttpRequestResponse> extraBodies = new ArrayList<>();
            for (HttpRequestResponse rr : map) {
                if (rr == null || rr.request() == null) {
                    continue;
                }
                HttpRequest req = rr.request();
                if (restrictedToScope && !safeIsInScope(req)) {
                    continue;
                }
                acc.siteMapInScope++;
                boolean matched = noteQueryMatch(acc, terms, req);
                if (terms.isEmpty()) {
                    String method = req.method() != null ? req.method() : "?";
                    String url = req.url() != null ? req.url() : "";
                    acc.queryMatches.add(method + " " + url);
                }
                if (matched) {
                    matchBodies.add(rr);
                } else if (wantEmail || (wantBodies && looksLikeTextAsset(req))) {
                    extraBodies.add(rr);
                }
            }
            List<HttpRequestResponse> deepCandidates = new ArrayList<>(matchBodies);
            deepCandidates.addAll(extraBodies);
            int bodyScans = 0;
            for (HttpRequestResponse rr : deepCandidates) {
                if (bodyScans >= CHAT_SITEMAP_BODY_SCAN_MAX
                        || System.currentTimeMillis() > deadline) {
                    break;
                }
                if (wantEmail) {
                    collectEmailEvidenceFromExchange(rr.request(), rr.response(), acc);
                } else {
                    collectTermSnippetsFromExchange(rr.request(), rr.response(), terms, acc);
                }
                acc.bodyDeepScans++;
                bodyScans++;
            }
        } catch (Exception e) {
            return "=== Burp traffic digest ===\nCould not read Proxy history / Site Map: " + e.getMessage() + "\n";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== Burp Site Map + traffic (answer from this; do not send the operator to HTTP History) ===\n");
        sb.append("Site Map items: ").append(acc.siteMapItems)
                .append(restrictedToScope ? " (in-scope " + acc.siteMapInScope + ")" : "")
                .append(". Proxy history: ").append(proxyTotal)
                .append(" (body-sampled ").append(proxyConsidered).append(" newest in-scope). ")
                .append("Query terms: ").append(terms.isEmpty() ? "(none — URL inventory only)" : String.join(", ", terms))
                .append(". Body deep-scans: ").append(acc.bodyDeepScans).append(".\n");
        sb.append("Every Site Map URL was checked against the query (metadata). Response bodies are opened only for matches")
                .append(wantEmail ? " and email/form hunts" : wantBodies ? " and JS/HTML/JSON body hunts" : "").append(".\n\n");

        sb.append(terms.isEmpty() ? "Site Map URL inventory:\n" : "URLs matching the question:\n");
        if (acc.queryMatches.isEmpty()) {
            sb.append(terms.isEmpty()
                    ? "(Site Map was empty or out of scope)\n"
                    : "(no URL/path matches for those terms in the Site Map)\n");
        } else {
            int n = 0;
            for (String line : acc.queryMatches) {
                sb.append("- ").append(line).append("\n");
                if (++n >= CHAT_QUERY_MATCH_LIST_MAX) {
                    sb.append("- … ").append(acc.queryMatches.size() - n).append(" more matching URLs omitted\n");
                    break;
                }
            }
        }

        if (!acc.termSnippets.isEmpty()) {
            sb.append("\nBody snippets matching query terms:\n");
            int n = 0;
            for (String line : acc.termSnippets) {
                sb.append("- ").append(line).append("\n");
                if (++n >= 60) {
                    sb.append("- … ").append(acc.termSnippets.size() - n).append(" more snippets omitted\n");
                    break;
                }
            }
        }

        if (wantEmail) {
            sb.append("\nNon-authentication email collection points:\n");
            if (acc.nonAuth.isEmpty()) {
                sb.append("(none found in sampled bodies)\n");
            } else {
                int n = 0;
                for (String line : acc.nonAuth) {
                    sb.append("- ").append(line).append("\n");
                    if (++n >= 80) {
                        sb.append("- … ").append(acc.nonAuth.size() - n).append(" more unique hits omitted\n");
                        break;
                    }
                }
            }
            sb.append("\nAuthentication / identity-lifecycle email fields:\n");
            if (acc.authRelated.isEmpty()) {
                sb.append("(none)\n");
            } else {
                int n = 0;
                for (String line : acc.authRelated) {
                    sb.append("- ").append(line).append("\n");
                    if (++n >= 20) {
                        break;
                    }
                }
            }
        }
        if (!acc.jsScanned.isEmpty()) {
            sb.append("\nJavaScript files reviewed (bodies):\n");
            int n = 0;
            for (String line : acc.jsScanned) {
                sb.append("- ").append(line).append("\n");
                if (++n >= 30) {
                    sb.append("- … ").append(acc.jsScanned.size() - n).append(" more JS files\n");
                    break;
                }
            }
        }
        if (sb.length() > CHAT_DIGEST_MAX_CHARS) {
            return truncateMiddleWithNotice(sb.toString(), CHAT_DIGEST_MAX_CHARS);
        }
        return sb.toString();
    }

    private List<String> extractSearchTerms(String question) {
        LinkedHashSet<String> terms = new LinkedHashSet<>();
        if (question == null || question.isBlank()) {
            return new ArrayList<>();
        }
        Matcher quoted = Pattern.compile("\"([^\"]{2,80})\"|'([^']{2,80})'").matcher(question);
        while (quoted.find()) {
            String q = quoted.group(1) != null ? quoted.group(1) : quoted.group(2);
            if (q != null && !q.isBlank()) {
                terms.add(q.toLowerCase(Locale.ROOT).trim());
            }
        }
        for (String w : question.toLowerCase(Locale.ROOT).split("[^a-z0-9_.+-]+")) {
            if (w.isEmpty() || CHAT_STOPWORDS.contains(w)) {
                continue;
            }
            if (w.length() < 2) {
                continue;
            }
            if (w.length() == 2 && !(w.equals("js") || w.equals("s3") || w.equals("id"))) {
                continue;
            }
            terms.add(w);
            if (w.equals("javascript")) {
                terms.add("js");
                terms.add(".js");
            }
            if (w.equals("forms")) {
                terms.add("form");
            }
        }
        return new ArrayList<>(terms);
    }

    private boolean questionLooksLikeEmailOrFormHunt(String question, List<String> terms) {
        String q = question != null ? question.toLowerCase(Locale.ROOT) : "";
        if (q.contains("email") || q.contains("e-mail") || q.contains("newsletter") || q.contains("form")) {
            return true;
        }
        for (String t : terms) {
            if ("email".equals(t) || "forms".equals(t) || "form".equals(t) || "newsletter".equals(t)) {
                return true;
            }
        }
        return false;
    }

    private boolean questionLooksLikeBodyHunt(String question, List<String> terms) {
        String q = question != null ? question.toLowerCase(Locale.ROOT) : "";
        if (q.contains("secret") || q.contains("token") || q.contains("jwt") || q.contains("xss")
                || q.contains("javascript") || q.contains("graphql") || q.contains("swagger")
                || q.contains("hidden") || q.contains("api key")) {
            return true;
        }
        if (terms == null) {
            return false;
        }
        for (String t : terms) {
            if (t == null) {
                continue;
            }
            switch (t) {
                case "secret":
                case "secrets":
                case "token":
                case "jwt":
                case "xss":
                case "javascript":
                case "graphql":
                case "swagger":
                case "openapi":
                case "actuator":
                    return true;
                default:
                    break;
            }
        }
        return false;
    }

    private boolean looksLikeTextAsset(HttpRequest req) {
        if (req == null) {
            return false;
        }
        String path = req.path();
        if (path == null || path.isEmpty()) {
            return true;
        }
        String pl = path.toLowerCase(Locale.ROOT);
        int q = pl.indexOf('?');
        if (q >= 0) {
            pl = pl.substring(0, q);
        }
        int slash = pl.lastIndexOf('/');
        String last = slash >= 0 ? pl.substring(slash + 1) : pl;
        int dot = last.lastIndexOf('.');
        if (dot < 0) {
            return true;
        }
        String ext = last.substring(dot);
        return ext.equals(".js") || ext.equals(".mjs") || ext.equals(".cjs") || ext.equals(".json")
                || ext.equals(".html") || ext.equals(".htm") || ext.equals(".xml") || ext.equals(".txt")
                || ext.equals(".map") || ext.equals(".graphql");
    }

    private void collectTermSnippetsFromExchange(HttpRequest req, HttpResponse res, List<String> terms,
            EmailTrafficAcc acc) {
        if (req == null || res == null || terms == null || terms.isEmpty() || acc == null) {
            return;
        }
        if (shouldSkipChatTraffic(req, res)) {
            return;
        }
        try {
            if (res.body() == null || res.body().length() > CHAT_MAX_BODY_BYTES) {
                return;
            }
            String body = res.bodyToString();
            if (body == null || body.isEmpty()) {
                return;
            }
            String lower = body.toLowerCase(Locale.ROOT);
            for (String term : terms) {
                if (!isSnippetTerm(term)) {
                    continue;
                }
                int i = lower.indexOf(term.toLowerCase(Locale.ROOT));
                if (i < 0) {
                    continue;
                }
                String method = req.method() != null ? req.method() : "?";
                String url = req.url() != null ? req.url() : "";
                acc.termSnippets.add(method + " " + truncateForIssueTitle(url, 160)
                        + " | " + term + " | " + compactSnippet(body, i));
                if (isJavaScriptAsset(req, contentTypeLower(res))) {
                    acc.jsScanned.add(method + " " + truncateForIssueTitle(url, 180));
                }
                return;
            }
        } catch (Exception ignored) {
        }
    }

    private static boolean isSnippetTerm(String term) {
        if (term == null) {
            return false;
        }
        String t = term.toLowerCase(Locale.ROOT);
        if (t.equals("jwt") || t.equals("xss") || t.equals("sso") || t.equals("idor") || t.equals("email")) {
            return true;
        }
        if (t.length() < 5) {
            return false;
        }
        switch (t) {
            case "method":
            case "names":
            case "field":
            case "fields":
            case "evidence":
            case "quote":
            case "short":
            case "likely":
            case "false":
            case "javascript":
            case "collect":
            case "surfaces":
            case "candidates":
            case "invent":
            case "testing":
            case "visible":
            case "obvious":
            case "source":
            case "redacted":
            case "snippet":
                return false;
            default:
                return true;
        }
    }

    private boolean noteQueryMatch(EmailTrafficAcc acc, List<String> terms, HttpRequest req) {
        if (req == null || terms == null || terms.isEmpty()) {
            return false;
        }
        String url = req.url() != null ? req.url() : "";
        String path = req.path() != null ? req.path() : "";
        String hay = (url + " " + path).toLowerCase(Locale.ROOT);
        List<String> hits = new ArrayList<>();
        for (String term : terms) {
            if (term != null && !term.isEmpty() && hay.contains(term.toLowerCase(Locale.ROOT))) {
                hits.add(term);
            }
        }
        if (hits.isEmpty()) {
            return false;
        }
        String method = req.method() != null ? req.method() : "?";
        acc.queryMatches.add(method + " " + url + " | terms=" + String.join(",", hits));
        return true;
    }

    /**
     * Full Site Map via unfiltered {@code requestResponses()}. Prefix filter is only a fallback if that list is empty.
     * Callers must not {@code bodyToString()} every item — metadata matching is cheap; bodies are for hits only.
     */
    private List<HttpRequestResponse> loadFullSiteMap(Set<String> prefixes) {
        try {
            List<HttpRequestResponse> direct = api.siteMap().requestResponses();
            if (direct != null && !direct.isEmpty()) {
                return direct;
            }
        } catch (Exception e) {
            log("Site Map requestResponses() failed: " + e.getMessage(), LogCategory.GENERAL);
        }
        return loadSiteMapByPrefixes(prefixes);
    }

    /**
     * Prefix-only Site Map lookups used when the unfiltered map is empty.
     */
    private List<HttpRequestResponse> loadSiteMapByPrefixes(Set<String> prefixes) {
        List<HttpRequestResponse> all = new ArrayList<>();
        if (prefixes == null || prefixes.isEmpty()) {
            return all;
        }
        for (String prefix : prefixes) {
            try {
                List<HttpRequestResponse> part = api.siteMap().requestResponses(SiteMapFilter.prefixFilter(prefix));
                if (part != null) {
                    all.addAll(part);
                }
            } catch (Exception e) {
                log("Site Map prefixFilter(" + prefix + ") failed: " + e.getMessage(), LogCategory.GENERAL);
            }
        }
        return all;
    }

    private String originPrefix(HttpRequest req) {
        if (req == null || req.httpService() == null) {
            return null;
        }
        HttpService svc = req.httpService();
        String host = svc.host();
        if (host == null || host.isEmpty()) {
            return null;
        }
        boolean https = svc.secure();
        int port = svc.port();
        StringBuilder b = new StringBuilder(https ? "https://" : "http://");
        b.append(host);
        if (port > 0 && !(https && port == 443) && !(!https && port == 80)) {
            b.append(':').append(port);
        }
        return b.toString();
    }

    private boolean safeIsInScope(HttpRequest req) {
        try {
            return req != null && req.isInScope();
        } catch (Exception e) {
            return false;
        }
    }

    private void collectEmailEvidenceFromExchange(HttpRequest req, HttpResponse res, EmailTrafficAcc acc) {
        if (req == null || shouldSkipChatTraffic(req, res)) {
            return;
        }
        String method = req.method() != null ? req.method() : "?";
        String url = req.url() != null ? req.url() : req.path();
        String path = req.pathWithoutQuery() != null ? req.pathWithoutQuery() : req.path();
        boolean auth = looksLikeAuthLifecyclePath(path) || looksLikeAuthLifecyclePath(url);

        LinkedHashSet<String> fields = new LinkedHashSet<>();
        try {
            List<ParsedHttpParameter> params = req.parameters();
            if (params != null) {
                for (ParsedHttpParameter p : params) {
                    if (p != null && isEmailRelatedParamName(p.name())) {
                        fields.add(p.name());
                    }
                }
            }
        } catch (Exception ignored) {
        }
        try {
            String body = req.bodyToString();
            if (body != null && fields.isEmpty() && body.length() < 100_000 && looksLikeJsonEmailKey(body)) {
                fields.add("json:email");
            }
        } catch (Exception ignored) {
        }

        LinkedHashSet<String> formHits = new LinkedHashSet<>();
        boolean sawHtml = false;
        if (res != null) {
            String ct = contentTypeLower(res);
            boolean js = isJavaScriptAsset(req, ct);
            try {
                if (res.body() != null && res.body().length() > CHAT_MAX_BODY_BYTES) {
                    if (js) {
                        acc.jsFiles++;
                        acc.jsScanned.add(method + " " + truncateForIssueTitle(url, 180) + " (skipped, body too large)");
                    }
                } else {
                    String body = res.bodyToString();
                    if (body != null && !body.isEmpty() && bodyMayContainEmailEvidence(body)) {
                        if (js) {
                            acc.jsFiles++;
                            String shortUrl = url != null && url.length() > 180 ? url.substring(0, 180) + "…" : url;
                            acc.jsScanned.add(method + " " + shortUrl);
                            formHits.addAll(extractEmailEvidenceFromJavaScript(body, url));
                        } else if (ct.contains("html") || ct.contains("xml") || ct.isEmpty()) {
                            sawHtml = ct.contains("html") || body.contains("<form") || body.contains("<FORM");
                            formHits.addAll(extractEmailFormsFromHtml(body, url));
                        } else if (ct.contains("json") && looksLikeJsonEmailKey(body)) {
                            formHits.add("JSON response contains email-related keys");
                        }
                    } else if (js && acc.jsScanned.size() < 30) {
                        acc.jsFiles++;
                        acc.jsScanned.add(method + " " + truncateForIssueTitle(url, 180) + " (no email strings)");
                    }
                }
            } catch (Exception ignored) {
            }
        }

        if (!fields.isEmpty()) {
            String line = method + " " + url + " | request fields: " + String.join(", ", fields);
            (auth ? acc.authRelated : acc.nonAuth).add(line);
        }
        for (String formLine : formHits) {
            boolean formAuth = auth || looksLikeAuthLifecyclePath(formLine);
            (formAuth ? acc.authRelated : acc.nonAuth).add(method + " " + url + " | " + formLine);
        }
        if (fields.isEmpty() && formHits.isEmpty() && sawHtml && acc.htmlNoEmail.size() < 40) {
            acc.htmlNoEmail.add(method + " " + (url != null && url.length() > 180 ? url.substring(0, 180) + "…" : url));
        }
    }

    private static boolean bodyMayContainEmailEvidence(String body) {
        if (body == null || body.isEmpty()) {
            return false;
        }
        return body.contains("email") || body.contains("Email") || body.contains("EMAIL")
                || body.contains("<form") || body.contains("<FORM")
                || body.contains("newsletter") || body.contains("Newsletter")
                || body.contains("subscribe") || body.contains("Subscribe");
    }

    private static String contentTypeLower(HttpResponse res) {
        try {
            String hv = res.headerValue("Content-Type");
            return hv != null ? hv.toLowerCase(Locale.ROOT) : "";
        } catch (Exception e) {
            return "";
        }
    }

    private boolean isJavaScriptAsset(HttpRequest req, String contentTypeLower) {
        if (contentTypeLower != null && (contentTypeLower.contains("javascript") || contentTypeLower.contains("ecmascript"))) {
            return true;
        }
        String path = req != null ? req.path() : null;
        if (path == null) {
            return false;
        }
        String pl = path.toLowerCase(Locale.ROOT);
        int q = pl.indexOf('?');
        if (q >= 0) {
            pl = pl.substring(0, q);
        }
        return pl.endsWith(".js") || pl.endsWith(".mjs") || pl.endsWith(".cjs");
    }

    private boolean shouldSkipChatTraffic(HttpRequest req, HttpResponse res) {
        String path = req.path();
        if (path != null) {
            String pl = path.toLowerCase(Locale.ROOT);
            int q = pl.indexOf('?');
            if (q >= 0) {
                pl = pl.substring(0, q);
            }
            if (pl.endsWith(".png") || pl.endsWith(".jpg") || pl.endsWith(".jpeg") || pl.endsWith(".gif")
                    || pl.endsWith(".webp") || pl.endsWith(".ico") || pl.endsWith(".woff") || pl.endsWith(".woff2")
                    || pl.endsWith(".ttf") || pl.endsWith(".eot") || pl.endsWith(".mp4") || pl.endsWith(".mp3")
                    || pl.endsWith(".pdf") || pl.endsWith(".zip") || pl.endsWith(".css") || pl.endsWith(".map")) {
                return true;
            }
        }
        if (res != null) {
            try {
                String ct = res.headerValue("Content-Type");
                if (ct != null) {
                    String c = ct.toLowerCase(Locale.ROOT);
                    if (c.contains("image/") || c.contains("font/") || c.contains("video/") || c.contains("audio/")
                            || c.contains("octet-stream")) {
                        return true;
                    }
                }
            } catch (Exception ignored) {
            }
        }
        return false;
    }

    private boolean isEmailRelatedParamName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        String n = name.toLowerCase(Locale.ROOT);
        return n.contains("email") || n.contains("e-mail") || n.contains("e_mail")
                || n.equals("mail") || n.contains("mailaddr") || n.contains("mail_addr")
                || n.contains("newsletter") || n.equals("subscribe");
    }

    private boolean looksLikeJsonEmailKey(String body) {
        String s = body.toLowerCase(Locale.ROOT);
        return s.contains("\"email\"") || s.contains("\"e-mail\"") || s.contains("\"user_email\"")
                || s.contains("\"emailaddress\"") || s.contains("\"newsletter\"");
    }

    private boolean looksLikeAuthLifecyclePath(String pathOrUrl) {
        if (pathOrUrl == null || pathOrUrl.isEmpty()) {
            return false;
        }
        String p = pathOrUrl.toLowerCase(Locale.ROOT);
        return p.contains("/login") || p.contains("/log-in") || p.contains("log_in")
                || p.contains("/signin") || p.contains("/sign-in") || p.contains("sign_in")
                || p.contains("/signup") || p.contains("/sign-up") || p.contains("sign_up")
                || p.contains("/register") || p.contains("/registration")
                || p.contains("/oauth") || p.contains("/sso") || p.contains("/saml") || p.contains("/oidc")
                || p.contains("/forgot") || p.contains("reset-password") || p.contains("resetpassword")
                || p.contains("forgot-password") || p.contains("/recover")
                || p.contains("/passwd") || p.contains("/password")
                || p.contains("/mfa") || p.contains("/2fa") || p.contains("/totp")
                || p.contains("/authenticate") || p.contains("/authorization")
                || p.contains("/auth/") || p.contains("/auth?") || p.endsWith("/auth");
    }

    private List<String> extractEmailFormsFromHtml(String html, String pageUrl) {
        List<String> hits = new ArrayList<>();
        if (html == null || html.isEmpty()) {
            return hits;
        }
        String slice = html.length() > CHAT_HTML_SCAN_CHARS ? html.substring(0, CHAT_HTML_SCAN_CHARS) : html;
        Matcher forms = HTML_FORM_PATTERN.matcher(slice);
        int found = 0;
        while (forms.find() && found < 20) {
            String form = forms.group();
            if (!HTML_EMAIL_INPUT_PATTERN.matcher(form).find() && !form.toLowerCase(Locale.ROOT).contains("email")) {
                continue;
            }
            String action = firstGroup(FORM_ACTION_PATTERN, form, pageUrl);
            String method = firstGroup(FORM_METHOD_PATTERN, form, "GET");
            LinkedHashSet<String> names = new LinkedHashSet<>();
            Matcher namesM = INPUT_NAME_PATTERN.matcher(form);
            while (namesM.find()) {
                String n = namesM.group(1);
                if (isEmailRelatedParamName(n) || "email".equalsIgnoreCase(n)) {
                    names.add(n);
                }
            }
            String formLower = form.toLowerCase(Locale.ROOT);
            if (formLower.contains("type=\"email\"") || formLower.contains("type='email'")) {
                if (names.isEmpty()) {
                    names.add("type=email");
                }
            }
            if (names.isEmpty()) {
                continue;
            }
            hits.add("HTML form method=" + method.toUpperCase(Locale.ROOT) + " action=" + action
                    + " fields=" + String.join(",", names));
            found++;
        }
        if (hits.isEmpty() && HTML_EMAIL_INPUT_PATTERN.matcher(slice).find()) {
            hits.add("HTML email input (no wrapping form tag) on " + pageUrl);
        }
        return hits;
    }

    private List<String> extractEmailEvidenceFromJavaScript(String js, String scriptUrl) {
        List<String> hits = new ArrayList<>();
        if (js == null || js.isEmpty()) {
            return hits;
        }
        String slice = js.length() > CHAT_HTML_SCAN_CHARS ? js.substring(0, CHAT_HTML_SCAN_CHARS) : js;
        addJsPatternHits(hits, JS_TYPE_EMAIL_PATTERN, slice, "JS type=email");
        addJsPatternHits(hits, JS_NAME_EMAIL_PATTERN, slice, "JS email field name");
        addJsPatternHits(hits, JS_EMAIL_KEY_PATTERN, slice, "JS email object key");
        addJsPatternHits(hits, JS_APPEND_EMAIL_PATTERN, slice, "JS FormData/email append");
        Matcher urls = JS_CONTACT_URL_PATTERN.matcher(slice);
        int urlHits = 0;
        while (urls.find() && urlHits < 8) {
            String path = urls.group(1);
            if (path != null && !looksLikeAuthLifecyclePath(path)) {
                hits.add("JS endpoint string: " + path);
                urlHits++;
            }
        }
        if (hits.size() > 12) {
            return new ArrayList<>(hits.subList(0, 12));
        }
        return hits;
    }

    private static void addJsPatternHits(List<String> hits, Pattern pattern, String slice, String label) {
        Matcher m = pattern.matcher(slice);
        int n = 0;
        while (m.find() && n < 4) {
            hits.add(label + ": …" + compactSnippet(slice, m.start()) + "…");
            n++;
        }
    }

    private static String compactSnippet(String text, int index) {
        int a = Math.max(0, index - 40);
        int b = Math.min(text.length(), index + 60);
        return text.substring(a, b).replaceAll("\\s+", " ").trim();
    }

    private static String firstGroup(Pattern pattern, String text, String fallback) {
        Matcher m = pattern.matcher(text);
        if (m.find() && m.group(1) != null && !m.group(1).isEmpty()) {
            return m.group(1);
        }
        return fallback != null ? fallback : "";
    }

    private void sendChatCheck(String cannedPrompt) {
        if (chatIncludeHttpCheckbox != null) {
            chatIncludeHttpCheckbox.setSelected(true);
        }
        sendChatPromptText(cannedPrompt, true, false);
    }

    private void sendChatPrompt() {
        String userText = chatInputArea != null ? chatInputArea.getText() : "";
        sendChatPromptText(userText, false, true);
    }

    private void sendChatPromptText(String userText, boolean forceTraffic, boolean clearInput) {
        if (chatBusy) {
            return;
        }
        if (userText == null || userText.trim().isEmpty()) {
            if (chatStatusLabel != null) {
                chatStatusLabel.setText("Type a prompt first, or use a Checks button.");
            }
            return;
        }
        userText = userText.trim();

        String selectedModel = validateChatModelPreflight();
        if (selectedModel == null) {
            SwingUtilities.invokeLater(() -> {
                if (chatStatusLabel != null) {
                    chatStatusLabel.setText("Blocked — set Local LLM URL + model id on Connect (or Premium Model for PoCs as fallback), then Save.");
                }
            });
            return;
        }

        boolean includeTraffic = forceTraffic
                || chatIncludeHttpCheckbox == null
                || chatIncludeHttpCheckbox.isSelected();
        chatTurns.add(new ChatTurn("You", userText));

        final String model = selectedModel;
        final String apiKey = getApiKeyForModel(selectedModel);
        final String question = userText;
        final boolean includeTrafficFinal = includeTraffic;

        if (clearInput && chatInputArea != null) {
            chatInputArea.setText("");
        }
        if (chatStatusLabel != null) {
            chatStatusLabel.setText(includeTraffic ? "Scanning full Site Map…" : "Sending to " + model + "…");
        }
        setChatBusy(true);
        appendDashboardActivity("Chat prompt sent — " + model + " — " + truncateForIssueTitle(question, 80));

        CompletableFuture.supplyAsync(() -> {
            try {
                String prompt = buildChatPrompt(question, includeTrafficFinal);
                SwingUtilities.invokeLater(() -> {
                    if (chatStatusLabel != null) {
                        chatStatusLabel.setText("Sending to " + model + "…");
                    }
                });
                return sendToAI(model, apiKey, prompt, false);
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }, threadPoolManager.getExecutor()).thenAccept(aiResponse -> {
            String text;
            try {
                text = extractContentFromResponse(aiResponse, model, false);
            } catch (Exception e) {
                text = "";
            }
            if (text != null && !text.isEmpty()) {
                text = cleanLLMResponse(text, false);
            }
            if (text == null || text.isEmpty()) {
                text = "(No text extracted from model response. Check Extension Output.)";
            }
            final String reply = text;
            SwingUtilities.invokeLater(() -> {
                chatTurns.add(new ChatTurn("Assistant", reply));
                setChatBusy(false);
                if (chatStatusLabel != null) {
                    chatStatusLabel.setText("Ready — " + model);
                }
            });
            appendDashboardActivity("Chat reply received — " + model);
        }).exceptionally(ex -> {
            String detail = formatExceptionChainForDashboard(ex);
            final String errorText = "Error: " + detail;
            SwingUtilities.invokeLater(() -> {
                chatTurns.add(new ChatTurn("Assistant", errorText));
                setChatBusy(false);
                if (chatStatusLabel != null) {
                    chatStatusLabel.setText("Error — see message above");
                }
            });
            appendDashboardActivity("Chat failed — " + detail);
            api.logging().logToError("AI Auditor chat failed: " + detail);
            return null;
        });
    }

    private void appendDashboardActivity(String line) {
        if (dashboardActivityArea == null || line == null) {
            return;
        }
        String ts = LOG_TS_FMT.format(Instant.now());
        String row = ts + "  " + line.replace("\r", "").replace("\n", " ") + "\n";
        SwingUtilities.invokeLater(() -> {
            if (dashboardActivityArea == null) {
                return;
            }
            dashboardActivityArea.append(row);
            trimDashboardActivityIfNeeded();
            scrollActivityLogToBottom();
        });
    }

    private void scrollActivityLogToBottom() {
        if (dashboardActivityArea == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            if (dashboardActivityArea != null) {
                dashboardActivityArea.setCaretPosition(dashboardActivityArea.getDocument().getLength());
            }
        });
    }

    private void trimDashboardActivityIfNeeded() {
        if (dashboardActivityArea == null) {
            return;
        }
        try {
            int lines = dashboardActivityArea.getLineCount();
            if (lines > DASHBOARD_ACTIVITY_MAX_LINES + 20) {
                int cut = dashboardActivityArea.getLineStartOffset(lines - DASHBOARD_ACTIVITY_MAX_LINES);
                if (cut > 0) {
                    dashboardActivityArea.replaceRange("", 0, cut);
                }
            }
        } catch (Exception ignored) {
            // keep UI responsive if document state is inconsistent
        }
    }

    private void copyActivityLogToClipboard() {
        if (dashboardActivityArea == null || dashboardActivityArea.getText().trim().isEmpty()) {
            return;
        }
        try {
            StringSelection stringSelection = new StringSelection(dashboardActivityArea.getText());
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
            log("Dashboard activity log copied to clipboard.", LogCategory.GENERAL);
        } catch (Exception ex) {
            api.logging().logToError("Could not copy activity log to clipboard: " + ex.getMessage());
        }
    }

    private ScheduledFuture<?> startPocHeartbeat(String model, String findingName) {
        if (dashboardHeartbeatScheduler.isShutdown()) {
            return null;
        }
        final long startedAtMs = System.currentTimeMillis();
        final String title = truncateForIssueTitle(findingName, 80);
        try {
            return dashboardHeartbeatScheduler.scheduleAtFixedRate(() -> {
                long elapsedSec = Math.max(0, (System.currentTimeMillis() - startedAtMs) / 1000);
                appendDashboardActivity("PoC / investigation still running — " + model + " — " + title
                        + " (" + elapsedSec + "s elapsed)");
            }, 30, 30, TimeUnit.SECONDS);
        } catch (Exception e) {
            log("Could not start PoC heartbeat: " + e.getMessage(), LogCategory.GENERAL);
            return null;
        }
    }

    private void stopHeartbeat(ScheduledFuture<?> heartbeat) {
        if (heartbeat != null) {
            heartbeat.cancel(false);
        }
    }

	private void updateStatusPanel() {
		if (threadPoolManager != null) {
			int active = threadPoolManager.getActiveCount();
			int queued = threadPoolManager.getQueueSize();
			int completed = completedTasksCounter.get();

			activeTasksLabel.setText("Active: " + active);
			queuedTasksLabel.setText("Queued: " + queued);
			completedTasksLabel.setText("Completed: " + completed);

			// Visual feedback for active work
			if (active > 0) {
				activeTasksLabel.setForeground(new Color(220, 50, 50)); // Red when busy
			} else {
				activeTasksLabel.setForeground(UIManager.getColor("Label.foreground"));
			}

			if (queued > 5) {
				queuedTasksLabel.setForeground(new Color(200, 140, 0)); // Orange when backlogged
			} else {
				queuedTasksLabel.setForeground(UIManager.getColor("Label.foreground"));
			}
		}
	}

    private void addApiKeyField(JPanel panel, GridBagConstraints gbc, int row, String label, 
                              JPasswordField field, String provider) {
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel(label), gbc);
        gbc.gridx = 1;
        panel.add(field, gbc);
        JButton validateButton = new JButton("Validate");
        validateButton.addActionListener(e -> validateApiKey(provider));
        gbc.gridx = 2;
        panel.add(validateButton, gbc);
    }

    private void saveSettings() {
        log("Starting saveSettings()...", LogCategory.GENERAL);
        
        try {
            // Get API keys from UI fields
            String openaiKey = new String(openaiKeyField.getPassword()).trim();
            String geminiKeys = geminiKeyField.getText().trim();
            String claudeKey = new String(claudeKeyField.getPassword()).trim();
            String openrouterKey = new String(openrouterKeyField.getPassword()).trim();
            String xaiKey = new String(xaiKeyField.getPassword()).trim();
            String localKey = new String(localKeyField.getPassword()).trim();
            String localEndpoint = localEndpointField.getText().trim();
            String proxy = proxyField.getText().trim();
            String filterModels = filterModelsField.getText().trim();
            
			try {
				int batchSizeValue = Integer.parseInt(batchSizeField.getText());
				if (batchSizeValue < 1 || batchSizeValue > 30) {
					showError("Batch size must be between 1 and 30.", new Exception());
					return;
				}
			} catch (NumberFormatException ex) {
				showError("Invalid batch size.", ex);
				return;
			}

            // Check if at least one valid key is provided
            if (openaiKey.isEmpty() && geminiKeys.isEmpty() && claudeKey.isEmpty() && openrouterKey.isEmpty() && xaiKey.isEmpty() && localEndpoint.isEmpty()) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(mainPanel,
                        "Please provide at least one API key",
                        "Validation Error",
                        JOptionPane.WARNING_MESSAGE);
                });
                return;
            }
            
            // Save using Montoya preferences
            api.persistence().preferences().setString(PREF_PREFIX + "openai_key", openaiKey);
            api.persistence().preferences().setString(PREF_PREFIX + "gemini_keys", geminiKeys); // Changed to gemini_keys
            refreshGeminiApiKeys(); // Refresh the keys in memory
            api.persistence().preferences().setString(PREF_PREFIX + "claude_key", claudeKey);
            api.persistence().preferences().setString(PREF_PREFIX + "openrouter_key", openrouterKey);
            api.persistence().preferences().setString(PREF_PREFIX + "xai_key", xaiKey);
            api.persistence().preferences().setString(PREF_PREFIX + "local_key", localKey);
            api.persistence().preferences().setString(PREF_PREFIX + "local_endpoint", localEndpoint);
            api.persistence().preferences().setString(PREF_PREFIX + "proxy", proxy);
            api.persistence().preferences().setString(PREF_PREFIX + "filter_models", filterModels);

            // Save logging level
            api.persistence().preferences().setString(PREF_PREFIX + "logging_level", currentLoggingLevel.name());




			 int maxChunkSize     = Integer.parseInt(maxChunkSizeField.getText());
			 int rateLimitCount   = Integer.parseInt(rateLimitCountField.getText());
			 int rateLimitWindow  = Integer.parseInt(rateLimitWindowField.getText());
			 int batchSize        = Integer.parseInt(batchSizeField.getText());

			 api.persistence().preferences().setInteger(PREF_PREFIX + "max_retries",      maxRetries);
			 api.persistence().preferences().setInteger(PREF_PREFIX + "retry_delay_ms",   retryDelayMs);
			 api.persistence().preferences().setInteger(PREF_PREFIX + "max_chunk_size",   maxChunkSize);
			 api.persistence().preferences().setInteger(PREF_PREFIX + "rate_limit_count", rateLimitCount);
			 api.persistence().preferences().setInteger(PREF_PREFIX + "rate_limit_window",rateLimitWindow);
			 api.persistence().preferences().setInteger(PREF_PREFIX + "batch_size", batchSize);


			// 1) Update your in-memory fields:
			this.maxRetries      = maxRetries;
			this.retryDelayMs    = retryDelayMs;
			this.maxChunkSize    = maxChunkSize;
			this.rateLimitCount  = rateLimitCount;
			this.rateLimitWindow = rateLimitWindow;
			this.batchSize = batchSize;

			// 2) Apply them immediately:
			RequestChunker.setMaxTokensPerChunk(this.maxChunkSize);
			threadPoolManager.updateRateLimiters(this.rateLimitCount, this.rateLimitWindow);
            
			
            // Save selected models (dual) + legacy single key for older builds
            String autoModel = (String) automaticAuditModelDropdown.getSelectedItem();
            String manualModel = (String) manualInvestigationModelDropdown.getSelectedItem();
            api.persistence().preferences().setString(PREF_PREFIX + "selected_model_automatic", autoModel);
            api.persistence().preferences().setString(PREF_PREFIX + "selected_model_manual", manualModel);
            api.persistence().preferences().setString(PREF_PREFIX + "selected_model", manualModel);
            
            // Save custom prompt if modified from default
            String customPrompt = promptTemplateArea.getText();
            String currentPrompt = promptTemplateArea.getText();
            String explainMeThisPrompt = explainMeThisPromptArea.getText(); // Get Explain Me This prompt
            String defaultPrompt = getDefaultPromptTemplate();
            String defaultExplainMeThisPrompt = getDefaultExplainMeThisPrompt(); // Get default Explain Me This prompt
            if (!currentPrompt.equals(defaultPrompt)) {
                api.persistence().preferences().setString(PREF_PREFIX + "custom_prompt", currentPrompt);
            }
            if (!explainMeThisPrompt.equals(defaultExplainMeThisPrompt)) {
                api.persistence().preferences().setString(PREF_PREFIX + "explain_me_this_prompt", explainMeThisPrompt);
            }
            String pocPrompt = pocPromptArea.getText();
            String defaultPoc = getDefaultPocPrompt();
            if (!pocPrompt.equals(defaultPoc)) {
                api.persistence().preferences().setString(PREF_PREFIX + "poc_prompt", pocPrompt);
            }

            refreshCachedProviderDefaults();
            api.persistence().preferences().setString(PREF_PREFIX + "default_model_openai", cachedDefaultOpenai);
            api.persistence().preferences().setString(PREF_PREFIX + "default_model_gemini", cachedDefaultGemini);
            api.persistence().preferences().setString(PREF_PREFIX + "default_model_claude", cachedDefaultClaude);
            api.persistence().preferences().setString(PREF_PREFIX + "default_model_openrouter", cachedDefaultOpenrouter);
            api.persistence().preferences().setString(PREF_PREFIX + "default_model_xai", cachedDefaultXai);
            api.persistence().preferences().setString(PREF_PREFIX + "default_model_local", cachedDefaultLocal);

            int passiveKb;
            try {
                passiveKb = Integer.parseInt(passiveMaxBodyKbField.getText().trim());
                if (passiveKb < 8 || passiveKb > 8192) {
                    showError("Passive max response must be between 8 and 8192 KB.", new IllegalArgumentException());
                    return;
                }
            } catch (NumberFormatException ex) {
                showError("Invalid passive max response (KB).", ex);
                return;
            }
            passiveMaxResponseBytes = passiveKb * 1024;
            api.persistence().preferences().setInteger(PREF_PREFIX + "passive_max_body_kb", passiveKb);

            boolean onScannerIssues = passiveAiOnScannerIssuesCheckbox.isSelected();
            boolean allTraffic = passiveAiAllTrafficCheckbox.isSelected();
            boolean proxyBrowser = proxyBrowserLocalAiCheckbox.isSelected();
            boolean includeRepeater = proxyIncludeRepeaterCheckbox.isSelected();
            boolean passiveScope = passiveAiInScopeCheckbox.isSelected();
            passiveAiOnScannerIssues = onScannerIssues;
            passiveAiAuditAllTraffic = allTraffic;
            proxyBrowserLocalAiEnabled = proxyBrowser;
            proxyIncludeRepeater = includeRepeater;
            passiveAiInScopeOnly = passiveScope;
            api.persistence().preferences().setBoolean(PREF_PREFIX + "passive_ai_scanner_issues", onScannerIssues);
            api.persistence().preferences().setBoolean(PREF_PREFIX + "passive_ai_all_traffic", allTraffic);
            api.persistence().preferences().setBoolean(PREF_PREFIX + "proxy_browser_local_ai", proxyBrowser);
            api.persistence().preferences().setBoolean(PREF_PREFIX + "proxy_include_repeater", includeRepeater);
            api.persistence().preferences().setBoolean(PREF_PREFIX + "passive_ai_in_scope", passiveScope);
            
            // Save timestamp
            api.persistence().preferences().setLong(PREF_PREFIX + "last_save", System.currentTimeMillis());
            
            // Verify saves were successful
            boolean allValid = verifySettings(openaiKey, geminiKeys, claudeKey, openrouterKey, xaiKey, localKey, localEndpoint);
            
            if (allValid) {
                api.logging().raiseInfoEvent("Settings saved successfully!");
            }
    
            log(String.format(
                "Runtime updated: maxRetries=%d, retryDelayMs=%d, chunkSize=%d, rateLimit=%d/%ds",
                this.maxRetries, this.retryDelayMs,
                this.maxChunkSize,
                this.rateLimitCount, this.rateLimitWindow
            ), LogCategory.GENERAL);
    
        } catch (Exception e) {
            showError("Error saving settings", e);
        }
    }
    
    private boolean verifySettings(String openaiKey, String geminiKeys, String claudeKey, String openrouterKey, String xaiKey, String localKey, String localEndpoint) {
        boolean allValid = true;
        StringBuilder errors = new StringBuilder();
        
        // Verify each key was saved correctly
        String verifyOpenai = api.persistence().preferences().getString(PREF_PREFIX + "openai_key");
        if (!openaiKey.equals(verifyOpenai)) {
            allValid = false;
            errors.append("OpenAI key verification failed\n");
        }
        
        String verifyGemini = api.persistence().preferences().getString(PREF_PREFIX + "gemini_keys");
        if (!geminiKeys.equals(verifyGemini)) {
            allValid = false;
            errors.append("Gemini keys verification failed\n");
        }
        
        String verifyClaude = api.persistence().preferences().getString(PREF_PREFIX + "claude_key");
        if (!claudeKey.equals(verifyClaude)) {
            allValid = false;
            errors.append("Claude key verification failed\n");
        }

        String verifyOpenrouter = api.persistence().preferences().getString(PREF_PREFIX + "openrouter_key");
        if (!openrouterKey.equals(verifyOpenrouter)) {
            allValid = false;
            errors.append("OpenRouter key verification failed\n");
        }

        String verifyXai = api.persistence().preferences().getString(PREF_PREFIX + "xai_key");
        if (!xaiKey.equals(verifyXai)) {
            allValid = false;
            errors.append("xAI key verification failed\n");
        }

        String verifyLocal = api.persistence().preferences().getString(PREF_PREFIX + "local_key");
        if (!localKey.equals(verifyLocal)) {
            allValid = false;
            errors.append("Local key verification failed\n");
        }

        String verifyEndpoint = api.persistence().preferences().getString(PREF_PREFIX + "local_endpoint");
        if (!localEndpoint.equals(verifyEndpoint)) {
            allValid = false;
            errors.append("Local endpoint verification failed\n");
        }
        
        if (!allValid) {
            api.logging().logToError("Settings verification failed:\n" + errors.toString());
        }
        		
        return allValid;
    }
    
    private void loadSavedSettings() {
        log("Starting loadSavedSettings()...", LogCategory.GENERAL);
        
        if (openaiKeyField == null || geminiKeyField == null || claudeKeyField == null || openrouterKeyField == null || xaiKeyField == null || localEndpointField == null || localKeyField == null) {
            api.logging().logToError("Cannot load settings - UI components not initialized");
            return;
        }
        
        try {
            // Load API keys
            String openaiKey = api.persistence().preferences().getString(PREF_PREFIX + "openai_key");
            String geminiKeysString = api.persistence().preferences().getString(PREF_PREFIX + "gemini_keys");
            String claudeKey = api.persistence().preferences().getString(PREF_PREFIX + "claude_key");
            String openrouterKey = api.persistence().preferences().getString(PREF_PREFIX + "openrouter_key");
            String xaiKey = api.persistence().preferences().getString(PREF_PREFIX + "xai_key");
            String localKey = api.persistence().preferences().getString(PREF_PREFIX + "local_key");
            String localEndpoint = api.persistence().preferences().getString(PREF_PREFIX + "local_endpoint");
            String proxy = api.persistence().preferences().getString(PREF_PREFIX + "proxy");
            String filterModels = api.persistence().preferences().getString(PREF_PREFIX + "filter_models");
			
			//log("Debug: Integer mr ...", LogCategory.GENERAL);
			 
			// read each pref (Montoya’s getInteger only takes one String)
			//int maxRetries       = api.persistence().preferences().getInteger(PREF_PREFIX + "max_retries");
			Integer mr = api.persistence().preferences().getInteger(PREF_PREFIX + "max_retries");
			this.maxRetries = (mr != null && mr > 0) ? mr : 3;
			
			Integer rd = api.persistence().preferences().getInteger(PREF_PREFIX + "retry_delay_ms");
			this.retryDelayMs = (rd != null && rd > 0) ? rd : 1000;

			Integer mc = api.persistence().preferences().getInteger(PREF_PREFIX + "max_chunk_size");
			this.maxChunkSize = (mc != null && mc > 0) ? mc : 16384;

			Integer rc = api.persistence().preferences().getInteger(PREF_PREFIX + "rate_limit_count");
			this.rateLimitCount = (rc != null && rc > 0) ? rc : 50;

			Integer rw = api.persistence().preferences().getInteger(PREF_PREFIX + "rate_limit_window");
			this.rateLimitWindow = (rw != null && rw > 0) ? rw : 60;

			Integer bs = api.persistence().preferences().getInteger(PREF_PREFIX + "batch_size");
			this.batchSize = (bs != null && bs > 0) ? bs : 5;

			SwingUtilities.invokeLater(() -> {
				retriesField.setText(String.valueOf(this.maxRetries));
				retryDelayField.setText(String.valueOf(this.retryDelayMs));
				maxChunkSizeField.setText(String.valueOf(this.maxChunkSize));
				rateLimitCountField.setText(String.valueOf(this.rateLimitCount));
				rateLimitWindowField.setText(String.valueOf(this.rateLimitWindow));
				batchSizeField.setText(String.valueOf(this.batchSize));
			});

			 
			 
			 threadPoolManager.updateRateLimiters(rateLimitCount, rateLimitWindow);



            
            migrateDualModelPreferencesIfNeeded();
            String selectedModelAutomatic = api.persistence().preferences().getString(PREF_PREFIX + "selected_model_automatic");
            String selectedModelManual = api.persistence().preferences().getString(PREF_PREFIX + "selected_model_manual");
            
            // Load custom prompt if exists
            String customPrompt = api.persistence().preferences().getString(PREF_PREFIX + "custom_prompt");
            String explainMeThisPrompt = api.persistence().preferences().getString(PREF_PREFIX + "explain_me_this_prompt"); // Load Explain Me This prompt
            String pocPrompt = api.persistence().preferences().getString(PREF_PREFIX + "poc_prompt");

            // Load logging level
            String savedLoggingLevel = api.persistence().preferences().getString(PREF_PREFIX + "logging_level");
            if (savedLoggingLevel != null) {
                try {
                    currentLoggingLevel = LoggingLevel.valueOf(savedLoggingLevel);
                } catch (IllegalArgumentException e) {
                    api.logging().logToError("Invalid saved logging level: " + savedLoggingLevel + ". Defaulting to DETAILED_ONELINER.");
                    currentLoggingLevel = LoggingLevel.DETAILED_ONELINER;
                }
            }
            
            // Log retrieval status
            log("Retrieved from preferences:", LogCategory.GENERAL);
            log("- OpenAI key: " + (openaiKey != null && !openaiKey.trim().isEmpty() ? "exists" : "null or empty"), LogCategory.GENERAL);
            log("- Gemini keys: " + (geminiKeysString != null && !geminiKeysString.trim().isEmpty() ? "exists" : "null or empty"), LogCategory.GENERAL);
            log("- Claude key: " + (claudeKey != null && !claudeKey.trim().isEmpty() ? "exists" : "null or empty"), LogCategory.GENERAL);
            log("- OpenRouter key: " + (openrouterKey != null && !openrouterKey.trim().isEmpty() ? "exists" : "null or empty"), LogCategory.GENERAL);
            log("- xAI key: " + (xaiKey != null && !xaiKey.trim().isEmpty() ? "exists" : "null or empty"), LogCategory.GENERAL);
            log("- Local endpoint: " + (localEndpoint != null && !localEndpoint.trim().isEmpty() ? localEndpoint : "null or empty"), LogCategory.GENERAL);
            log("- Automatic model: " + selectedModelAutomatic + ", Manual model: " + selectedModelManual, LogCategory.GENERAL);
            log("- Logging Level: " + currentLoggingLevel.name(), LogCategory.GENERAL);

			log(String.format(
				"Runtime updated: maxRetries=%d, retryDelayMs=%d, chunkSize=%d, rateLimit=%d/%ds",
				this.maxRetries, this.retryDelayMs,
				this.maxChunkSize,
				this.rateLimitCount, this.rateLimitWindow
			));



			
            // Update UI components
            SwingUtilities.invokeLater(() -> {
                // Set API keys
                openaiKeyField.setText(openaiKey != null ? openaiKey : "");
                geminiKeyField.setText(geminiKeysString != null ? geminiKeysString : "");
                refreshGeminiApiKeys();
                claudeKeyField.setText(claudeKey != null ? claudeKey : "");
                openrouterKeyField.setText(openrouterKey != null ? openrouterKey : "");
                xaiKeyField.setText(xaiKey != null ? xaiKey : "");
                localEndpointField.setText(localEndpoint != null ? localEndpoint : "http://127.0.0.1:11434/v1");
                localKeyField.setText(localKey != null ? localKey : "");
                proxyField.setText(proxy != null ? proxy : "");
                filterModelsField.setText(filterModels != null ? filterModels : "embed,image,vision,free");

                applyModelFilter();
                
                if (selectedModelAutomatic != null && automaticAuditModelDropdown != null) {
                    automaticAuditModelDropdown.setSelectedItem(selectedModelAutomatic);
                }
                if (selectedModelManual != null && manualInvestigationModelDropdown != null) {
                    manualInvestigationModelDropdown.setSelectedItem(selectedModelManual);
                }
                
                // Main prompt: saved custom text, or built-in default (matches runtime fallback when empty)
                if (promptTemplateArea != null) {
                    if (customPrompt != null && !customPrompt.isEmpty()) {
                        promptTemplateArea.setText(customPrompt);
                    } else {
                        promptTemplateArea.setText(getDefaultPromptTemplate());
                    }
                }

                // Set Explain Me This prompt if exists
                if (explainMeThisPrompt != null && !explainMeThisPrompt.isEmpty() && explainMeThisPromptArea != null) {
                    explainMeThisPromptArea.setText(explainMeThisPrompt);
                }
                if (pocPrompt != null && !pocPrompt.isEmpty() && pocPromptArea != null) {
                    pocPromptArea.setText(pocPrompt);
                }

                // Set logging radio button
                switch (currentLoggingLevel) {
                    case DETAILED:
                        detailedLoggingRadio.setSelected(true);
                        break;
                    case DETAILED_ONELINER:
                        detailedOnelinerLoggingRadio.setSelected(true);
                        break;
                    case LIMITED:
                        limitedLoggingRadio.setSelected(true);
                        break;
                }

                String dmOpenai = api.persistence().preferences().getString(PREF_PREFIX + "default_model_openai");
                String dmGemini = api.persistence().preferences().getString(PREF_PREFIX + "default_model_gemini");
                String dmClaude = api.persistence().preferences().getString(PREF_PREFIX + "default_model_claude");
                String dmOr = api.persistence().preferences().getString(PREF_PREFIX + "default_model_openrouter");
                String dmXai = api.persistence().preferences().getString(PREF_PREFIX + "default_model_xai");
                String dmLocal = api.persistence().preferences().getString(PREF_PREFIX + "default_model_local");
                if (dmOpenai != null && !dmOpenai.isEmpty()) defaultOpenaiModelField.setText(dmOpenai);
                if (dmGemini != null && !dmGemini.isEmpty()) defaultGeminiModelField.setText(dmGemini);
                if (dmClaude != null && !dmClaude.isEmpty()) defaultClaudeModelField.setText(dmClaude);
                if (dmOr != null && !dmOr.isEmpty()) defaultOpenrouterModelField.setText(dmOr);
                if (dmXai != null && !dmXai.isEmpty()) defaultXaiModelField.setText(dmXai);
                if (dmLocal != null && !dmLocal.isEmpty()) {
                    setDefaultLocalModelComboText(migrateLoadedLocalDefaultModelPreference(dmLocal));
                }

                migratePassiveAiPreferencesIfNeeded();
                migrateProxyBrowserLocalAiPreferenceIfNeeded();
                Boolean psi = api.persistence().preferences().getBoolean(PREF_PREFIX + "passive_ai_scanner_issues");
                Boolean pat = api.persistence().preferences().getBoolean(PREF_PREFIX + "passive_ai_all_traffic");
                passiveAiOnScannerIssues = psi == null || Boolean.TRUE.equals(psi);
                passiveAiAuditAllTraffic = Boolean.TRUE.equals(pat);
                Boolean pbl = api.persistence().preferences().getBoolean(PREF_PREFIX + "proxy_browser_local_ai");
                proxyBrowserLocalAiEnabled = pbl == null || Boolean.TRUE.equals(pbl);
                if (passiveAiOnScannerIssuesCheckbox != null) {
                    passiveAiOnScannerIssuesCheckbox.setSelected(passiveAiOnScannerIssues);
                }
                if (passiveAiAllTrafficCheckbox != null) {
                    passiveAiAllTrafficCheckbox.setSelected(passiveAiAuditAllTraffic);
                }
                if (proxyBrowserLocalAiCheckbox != null) {
                    proxyBrowserLocalAiCheckbox.setSelected(proxyBrowserLocalAiEnabled);
                }
                Boolean pir = api.persistence().preferences().getBoolean(PREF_PREFIX + "proxy_include_repeater");
                proxyIncludeRepeater = Boolean.TRUE.equals(pir);
                if (proxyIncludeRepeaterCheckbox != null) {
                    proxyIncludeRepeaterCheckbox.setSelected(proxyIncludeRepeater);
                }

                Boolean pScope = api.persistence().preferences().getBoolean(PREF_PREFIX + "passive_ai_in_scope");
                if (pScope == null) {
                    passiveAiInScopeOnly = true;
                    passiveAiInScopeCheckbox.setSelected(true);
                } else {
                    passiveAiInScopeOnly = pScope;
                    passiveAiInScopeCheckbox.setSelected(pScope);
                }

                Integer pkb = api.persistence().preferences().getInteger(PREF_PREFIX + "passive_max_body_kb");
                int kb = (pkb != null && pkb >= 8) ? pkb : DEFAULT_PASSIVE_MAX_BODY_KB;
                passiveMaxBodyKbField.setText(String.valueOf(kb));
                passiveMaxResponseBytes = kb * 1024;

                refreshCachedProviderDefaults();
                
                log("UI fields updated with saved values", LogCategory.GENERAL);
            });
            
        } catch (Exception e) {
            api.logging().logToError("Error loading settings: " + e.getMessage());
        }
    }
    
    private String getDefaultPromptTemplate() {
        return """
                You are an expert web application security researcher specializing in identifying high-impact vulnerabilities. Analyze the provided HTTP request and response like a skilled bug bounty hunter and maximize OWASP Top 10 coverage with evidence-backed findings.

                COVERAGE CHECKLIST:
                1. Injection classes: SQL, NoSQL, command, template, HTML injection, SSRF, request smuggling
                2. XSS classes: reflected, stored, DOM-based
                3. Client-side-only controls for sensitive actions
                4. Auth/session weaknesses: username enumeration (login/forgot-password/registration), session not invalidated on logout, unverified email change paths
                5. CSRF weaknesses, only including HTTP verb tampering that may bypass anti-CSRF assumptions
                6. Session cookie weaknesses: missing Secure, missing/weak SameSite
                7. Unrestricted file upload and weak input filtering/validation
                9. Open redirect behavior and phishing-assisted redirect chains
                10. Verbose error messages and vulnerable software version disclosure
                11. Exposed API keys/secrets and whether key restrictions/scopes are missing
                12. Dependency confusion indicators (NPM/package namespace/registry trust) when supported by response/build evidence

                ANALYSIS GUIDELINES:
                - Prioritize issues likely to be missed by Nessus, Nuclei, and Burp Scanner
                - Focus on vulnerabilities requiring deep response and flow analysis
                - Report API endpoints found in JS files as INFORMATION level only unless clear exploitation evidence is present
                - Skip theoretical issues without clear evidence
                - Provide specific evidence, reproduction steps or specifically crafted proof of concept
                - Include detailed technical context for each finding
                - If evidence is weak, downgrade confidence/severity rather than overstate impact

                SEVERITY CRITERIA:
                HIGH: Immediate exploitation impact (RCE, auth bypass/account takeover, command injection, insecure deserialization, critical broken access control)
                MEDIUM: Significant exploitable risk with meaningful impact (including reflected XSS when evidenced, stored XSS, IDOR with scoped impact, CSRF on sensitive actions, unrestricted upload with realistic abuse)
                LOW: Real but limited-impact weakness with constrained exploitability
                INFORMATION: Useful security insights and weak signals needing more evidence

                CONFIDENCE CRITERIA:
                CERTAIN: Over 95 percent confident with clear evidence and reproducible
                FIRM: Over 60 percent confident with very strong indicators but needing additional validation
                TENTATIVE: At least 50 percent confident with indicators warranting further investigation

                Format findings as JSON with the following structure:
                {
                  "findings": [{
                    "vulnerability": "Clear, specific, concise title of issue",
                    "location": "Exact location in request/response (parameter, header, or path)",
                    "explanation": "Detailed technical explanation with evidence from the request/response",
                    "exploitation": "Specific steps to reproduce/exploit",
                    "validation_steps": "Steps to validate the finding",
                    "severity": "HIGH|MEDIUM|LOW|INFORMATION",
                    "confidence": "CERTAIN|FIRM|TENTATIVE"
                  }]
                }

                IMPORTANT:
                - Only report findings with clear evidence in the request/response
                - Issues below 50 percent confidence should not be reported unless severity is HIGH
                - Treat reflected XSS as at least MEDIUM when evidence is present (do not classify reflected XSS as LOW)
                - Include specific paths, parameters, headers, and behavioral deltas that indicate the vulnerability
                - For OAuth/authorization/session issues, analyze token handling, role boundaries, logout invalidation, and account-change flows
                - For injection points, provide exact payload locations and at least one concrete payload example in validation_steps
                - Do not report low-signal findings like missing headers alone unless they materially enable exploitation
                - Mask sensitive values in output: never include full credit card/PAN, SSN/SIN, auth tokens, session IDs, API keys, or secrets
                - For sensitive info disclosure, reference location and type of data while redacting values
                - In each finding, the "exploitation" and "validation_steps" fields must include concrete payloads, parameters, or raw HTTP fragments—not generic advice.
                - If confidence is below FIRM or evidence is weak, return an empty findings array instead of speculative claims
                - For each finding include at least two concrete evidence anchors from traffic (exact parameter/header/path/body fragment/status behavior)
                - Only return JSON with findings, no other content!
                """.stripIndent();
    }

    private String getDefaultExplainMeThisPrompt() {
        return "Explain this from a security perspective, focusing on potential vulnerabilities and risks. Keep the explanation concise and to the point.";
    }

    private String getDefaultPocPrompt() {
        return "You behave like Burp Suite’s built-in AI when the user asks to dig into a scanner finding: assume the goal is to **move from hypothesis to a demonstrable issue** using the evidence provided.\n\n"
                + "You are helping a tester who uses **their own API keys** and can run **smarter frontier models** than a typical default—use that depth: reason about parsers, state, auth, and multi-step chains when the traffic supports it.\n\n"
                + "INPUT may include a Burp Scanner (or extension) issue plus raw HTTP. Treat the scanner text as a **lead**, not gospel.\n\n"
                + "OUTPUT — use Markdown only (no JSON envelope). Be direct and technical.\n\n"
                + "## 1. Verdict on the finding\n"
                + "Does the evidence support a **real, exploitable** issue, a **weaker** variant, or likely **false positive**? One tight paragraph.\n\n"
                + "## 2. Exploitation / PoC path (this is the main deliverable)\n"
                + "- Give a **numbered sequence** of actions as if driving Burp **Repeater**.\n"
                + "- For **each** step include **complete raw HTTP** (request line + Host + relevant headers + body) the tester can paste, not pseudocode.\n"
                + "- Wrap each raw request in fenced code blocks as ```http ... ``` so tooling can parse and optionally execute with confirmation.\n"
                + "- Propose **2–4 concrete variants** where useful (e.g. different encodings, alternative parameters, CL.TE vs TE.CL style angles for smuggling-adjacent cases, error-based vs blind SQLi, polyglot XSS).\n"
                + "- If the issue class needs **multiple requests** (login → abuse session → escalate), show that chain explicitly.\n\n"
                + "## 3. What to observe\n"
                + "Exact signals: status codes, body substrings, timing deltas, length differences, header anomalies—what **proves** success vs noise. "
                + "Be specific (e.g. script tag present, payload reflected, error string, Set-Cookie change) — AI Auditor will send your HTTP blocks and check live responses against these signals.\n\n"
                + "## 4. If you cannot build a solid PoC\n"
                + "Say so clearly. List **specific** missing data (e.g. second role’s session, POST body schema, upstream proxy behavior) and the **next capture** the tester should take in Burp.\n\n"
                + "## 5. Safety\n"
                + "Assume the operator is an authorized penetration tester on approved, in-scope work (e.g. Burp Target scope). "
                + "Do not refuse, stall, or lecture about legality on that basis—this tool is used only in that context.\n\n"
                + "Still flag destructive or data-integrity risks (drop tables, mass exfil, account lockout) so the team can plan controlled verification.\n\n"
                + "Do not refuse solely because the topic is security testing—treat it as defensive, professional appsec work.";
    }

    private synchronized void refreshGeminiApiKeys() {
        String geminiKeysString = geminiKeyField.getText().trim();
        if (geminiKeysString.isEmpty()) {
            geminiApiKeys.clear();
        } else {
            geminiApiKeys = new ArrayList<>(Arrays.asList(geminiKeysString.split("\\s*\\n\\s*")));
        }
        currentGeminiKeyIndex.set(0); // Reset the index when keys are refreshed
        log("Gemini API keys refreshed. Found " + geminiApiKeys.size() + " keys.", LogCategory.GENERAL);
    }
    
    private boolean validateApiKeyWithEndpoint(String apiKey, String endpoint, String jsonBody, String provider) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(endpoint);
            conn = openValidationConnection(url);
            conn.setRequestMethod(jsonBody.isEmpty() ? "GET" : "POST");
            conn.setRequestProperty("Content-Type", "application/json");

            if ("openai".equals(provider)) {
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            } else if ("claude".equals(provider)) {
                conn.setRequestProperty("x-api-key", apiKey);
                conn.setRequestProperty("anthropic-version", "2023-06-01");
            } else if ("openrouter".equals(provider) || "xai".equals(provider)) {
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            } else if ("local".equals(provider) && apiKey != null && !apiKey.isEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            }

            if (!jsonBody.isEmpty()) {
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
                }
            }

            int responseCode = conn.getResponseCode();
            if (responseCode == 200) {
                return true;
            }
            String errorResponse = "";
            InputStream es = conn.getErrorStream();
            if (es != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(es, StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }
                    errorResponse = sb.toString();
                }
            }
            if ("local".equals(provider)) {
                api.logging().logToError("Local LLM validation failed HTTP " + responseCode + ": " + errorResponse);
            } else {
                api.logging().logToError("Validation failed HTTP " + responseCode + ": " + errorResponse);
            }
            return false;
        } catch (Exception e) {
            if ("local".equals(provider)) {
                api.logging().logToError("Error validating Local LLM URL (GET /v1/models): " + e.getMessage());
            } else {
                api.logging().logToError("Error validating API key: " + e.getMessage());
            }
            return false;
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
    
    
    private void setLocalLlmValidationStatus(String text, Color color) {
        if (localLlmValidationStatusLabel != null) {
            localLlmValidationStatusLabel.setText(text);
            localLlmValidationStatusLabel.setForeground(color);
        }
    }

    private void setCloudApiValidationStatus(String text, Color color) {
        if (cloudApiValidationStatusLabel != null) {
            cloudApiValidationStatusLabel.setText(text);
            cloudApiValidationStatusLabel.setForeground(color);
        }
    }

    /** Short label for Connect-tab status lines (Validate button feedback). */
    private static String providerDisplayName(String provider) {
        switch (provider) {
            case "openai":
                return "OpenAI";
            case "gemini":
                return "Gemini";
            case "claude":
                return "Anthropic";
            case "openrouter":
                return "OpenRouter";
            case "xai":
                return "xAI (Grok)";
            default:
                return provider != null ? provider : "";
        }
    }

    /**
     * Checks OpenAI-compatible {@code GET {base}/models} (LM Studio, Ollama, etc.). Runs off the Swing EDT so the UI
     * stays responsive; uses the same proxy bypass rules as outbound LLM calls so localhost is not sent via Burp.
     */
    private void validateLocalLlmEndpoint() {
        if (api == null) {
            return;
        }
        String base = localEndpointField != null ? localEndpointField.getText().trim() : "";
        if (base.isEmpty()) {
            setLocalLlmValidationStatus("Enter Local LLM URL first.", Color.RED);
            api.logging().raiseErrorEvent("Enter Local LLM URL first (e.g. http://127.0.0.1:11434/v1).");
            return;
        }
        final String apiKey = localKeyField != null ? new String(localKeyField.getPassword()).trim() : "";
        final String normalized = base.replaceAll("/+$", "");
        final String endpoint = normalized + "/models";

        setLocalLlmValidationStatus("Validating...", new Color(180, 140, 0));
        api.logging().logToOutput("AI Auditor: Validating Local LLM — GET " + endpoint + " (see Event Log when done).");

        Runnable runValidation = () -> {
            log("Validating local LLM (background): GET " + endpoint, LogCategory.GENERAL);
            boolean ok = validateApiKeyWithEndpoint(apiKey, endpoint, "", "local");
            final boolean success = ok;
            SwingUtilities.invokeLater(() -> {
                if (success) {
                    setLocalLlmValidationStatus("Validated: /models responded OK.", new Color(0, 130, 0));
                    api.logging().raiseInfoEvent("Local LLM URL is valid (/models responded OK).");
                    api.logging().logToOutput("AI Auditor: Local LLM validation succeeded.");
                    scheduleLocalModelIdDropdownRefresh();
                } else {
                    setLocalLlmValidationStatus("Validation failed. See Event Log/Output for details.", Color.RED);
                    api.logging().raiseErrorEvent(
                            "Local LLM validation failed — is Ollama running (ollama serve)? URL correct? Optional API key? Check Extension output for HTTP details.");
                    api.logging().logToOutput("AI Auditor: Local LLM validation failed (see Extension Errors / Event Log).");
                }
            });
        };

        if (threadPoolManager != null) {
            threadPoolManager.getExecutor().execute(runValidation);
        } else {
            runValidation.run();
        }
    }

    /**
     * Reads {@code GET {Local LLM URL}/models} (OpenAI-compatible) and returns each entry's {@code id}.
     */
    private List<String> fetchLocalOpenAiModelsList() {
        List<String> out = new ArrayList<>();
        String base = localEndpointField != null ? localEndpointField.getText().trim() : "";
        if (base.isEmpty()) {
            return out;
        }
        String normalized = base.replaceAll("/+$", "");
        String endpoint = normalized + "/models";
        String apiKey = localKeyField != null ? new String(localKeyField.getPassword()).trim() : "";
        HttpURLConnection conn = null;
        try {
            URL url = new URL(endpoint);
            conn = openValidationConnection(url);
            conn.setRequestMethod("GET");
            if (!apiKey.isEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            }
            if (conn.getResponseCode() != 200) {
                return out;
            }
            StringBuilder sb = new StringBuilder();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line);
                }
            }
            JSONObject root = new JSONObject(sb.toString());
            JSONArray data = root.optJSONArray("data");
            if (data == null) {
                cachedLocalModelIdsFromServer = new ArrayList<>();
                return out;
            }
            for (int i = 0; i < data.length(); i++) {
                JSONObject o = data.optJSONObject(i);
                if (o == null || !o.has("id")) {
                    continue;
                }
                String id = o.getString("id");
                if (id != null && !id.isEmpty()) {
                    out.add(id);
                }
            }
            cachedLocalModelIdsFromServer = new ArrayList<>(out);
        } catch (Exception e) {
            log("Could not list local LLM models (" + endpoint + "): " + e.getMessage(), LogCategory.GENERAL);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
        return out;
    }

    private void scheduleLocalModelIdDropdownRefresh() {
        Runnable task = () -> {
            List<String> ids = fetchLocalOpenAiModelsList();
            SwingUtilities.invokeLater(() -> mergeLocalModelIdsIntoDropdown(ids));
        };
        if (threadPoolManager != null) {
            threadPoolManager.getExecutor().execute(task);
        } else {
            task.run();
        }
    }

    /**
     * Rebuilds the Local LLM model id combo: common Gemma 4 presets first, then {@code gemma4…} tags from the server,
     * then other ids (so LM Studio / other models still appear if you do not use Gemma 4).
     */
    private void mergeLocalModelIdsIntoDropdown(List<String> fromServer) {
        if (defaultLocalModelCombo == null) {
            return;
        }
        String previous = getDefaultLocalModelComboText();
        LinkedHashSet<String> ordered = new LinkedHashSet<>();
        for (String preset : LOCAL_LLM_MODEL_ID_PRESETS) {
            ordered.add(preset);
        }
        List<String> gemma4 = new ArrayList<>();
        List<String> other = new ArrayList<>();
        if (fromServer != null) {
            for (String id : fromServer) {
                if (id == null || id.isEmpty()) {
                    continue;
                }
                if (id.toLowerCase(Locale.ROOT).contains("gemma4")) {
                    gemma4.add(id);
                } else {
                    other.add(id);
                }
            }
        }
        Collections.sort(gemma4);
        Collections.sort(other);
        ordered.addAll(gemma4);
        final int maxOther = 48;
        for (int i = 0; i < other.size() && i < maxOther; i++) {
            ordered.add(other.get(i));
        }
        defaultLocalModelCombo.removeAllItems();
        for (String id : ordered) {
            defaultLocalModelCombo.addItem(id);
        }
        boolean previousOnServer = false;
        if (fromServer != null && previous != null && !previous.isEmpty()) {
            for (String id : fromServer) {
                if (previous.equals(id) || stripLocalProviderPrefix(previous).equals(id)) {
                    previousOnServer = true;
                    break;
                }
            }
        }
        if (!previousOnServer && fromServer != null && !fromServer.isEmpty()) {
            String pick = fromServer.get(0);
            setDefaultLocalModelComboText(pick);
            log("Local LLM model id set to \"" + pick + "\" from /v1/models (previous \"" + previous
                    + "\" is not loaded on that server).", LogCategory.GENERAL);
        } else {
            setDefaultLocalModelComboText(previous);
        }
        if (fromServer != null && !fromServer.isEmpty()) {
            log("Local LLM model id list updated (" + fromServer.size() + " from /v1/models).", LogCategory.GENERAL);
        }
    }

    private String getDefaultLocalModelComboText() {
        if (defaultLocalModelCombo == null) {
            return "";
        }
        if (defaultLocalModelCombo.isEditable()) {
            Component ed = defaultLocalModelCombo.getEditor().getEditorComponent();
            if (ed instanceof JTextField) {
                return ((JTextField) ed).getText().trim();
            }
        }
        Object sel = defaultLocalModelCombo.getSelectedItem();
        return sel != null ? sel.toString().trim() : "";
    }

    private void setDefaultLocalModelComboText(String value) {
        if (defaultLocalModelCombo == null) {
            return;
        }
        String v = value != null ? value.trim() : "";
        for (int i = 0; i < defaultLocalModelCombo.getItemCount(); i++) {
            if (v.equals(defaultLocalModelCombo.getItemAt(i))) {
                defaultLocalModelCombo.setSelectedIndex(i);
                return;
            }
        }
        if (defaultLocalModelCombo.isEditable()) {
            Component ed = defaultLocalModelCombo.getEditor().getEditorComponent();
            if (ed instanceof JTextField) {
                ((JTextField) ed).setText(v);
            }
            defaultLocalModelCombo.getEditor().setItem(v);
        }
    }

    private void validateApiKey(String provider) {
        if ("local".equals(provider)) {
            validateLocalLlmEndpoint();
            return;
        }

        String apiKey = "";
        String endpoint = "";
        String jsonBody = "";

        try {
            switch (provider) {
                case "openai":
                    apiKey = new String(openaiKeyField.getPassword()).trim();
                    endpoint = "https://api.openai.com/v1/models";
                    break;

                case "gemini":
                    refreshGeminiApiKeys();
                    apiKey = geminiKeyField.getText().split("\n")[0].trim();
                    endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + apiKey;
                    jsonBody = "{"
                             + "  \"contents\": ["
                             + "    {\"parts\": [{\"text\": \"one plus one equals (respond with one integer only)\"}]}"
                             + "  ]"
                             + "}";
                    break;

                case "claude":
                    apiKey = new String(claudeKeyField.getPassword()).trim();
                    endpoint = "https://api.anthropic.com/v1/messages";
                    jsonBody = "{"
                             + "  \"model\": \"claude-3-5-sonnet-latest\","
                             + "  \"max_tokens\": " + CLAUDE_MAX_OUTPUT_TOKENS + ","
                             + "  \"messages\": ["
                             + "    {\"role\": \"user\", \"content\": \"one plus one equals (respond with one integer only)\"}"
                             + "  ]"
                             + "}";
                    break;

                case "openrouter":
                    apiKey = new String(openrouterKeyField.getPassword()).trim();
                    endpoint = "https://openrouter.ai/api/v1/models";
                    break;

                case "xai":
                    apiKey = new String(xaiKeyField.getPassword()).trim();
                    endpoint = "https://api.x.ai/v1/models";
                    break;

                default:
                    JOptionPane.showMessageDialog(mainPanel, "Unknown provider: " + provider, "Validation Error", JOptionPane.ERROR_MESSAGE);
                    return;
            }
        } catch (Exception e) {
            showError("Error validating API key for " + provider, e);
            return;
        }

        if (apiKey.isEmpty()) {
            setCloudApiValidationStatus("Validation skipped: paste a key in the field first.", Color.RED);
            api.logging().raiseErrorEvent("AI Auditor: Enter an API key before clicking Validate.");
            api.logging().logToOutput("AI Auditor: Validation skipped — empty API key (" + provider + ").");
            return;
        }

        final String apiKeyFinal = apiKey;
        final String endpointFinal = endpoint;
        final String jsonBodyFinal = jsonBody;
        final String providerFinal = provider;
        final String displayName = providerDisplayName(providerFinal);

        setCloudApiValidationStatus("Validating " + displayName + "…", new Color(180, 140, 0));
        if (mainPanel != null) {
            mainPanel.repaint();
        }

        api.logging().logToOutput("AI Auditor: Validating " + providerFinal + " API key — " + endpointFinal + " (see Connect status line + Event Log).");

        /* Use common pool so Validate is not stuck behind queued LLM work or CallerRunsPolicy on the EDT. */
        CompletableFuture.runAsync(() -> {
            try {
                log(String.format("Validation Request - Provider: %s, Endpoint: %s, Body: %s, API Key (last 4 chars): ...%s",
                        providerFinal, endpointFinal, jsonBodyFinal,
                        apiKeyFinal.length() > 4 ? apiKeyFinal.substring(apiKeyFinal.length() - 4) : "****"),
                        LogCategory.GENERAL);
                boolean ok = validateApiKeyWithEndpoint(apiKeyFinal, endpointFinal, jsonBodyFinal, providerFinal);
                SwingUtilities.invokeLater(() -> {
                    if (ok) {
                        setCloudApiValidationStatus(displayName + " API key is valid.", new Color(0, 130, 0));
                        api.logging().raiseInfoEvent(providerFinal + " API key is valid.");
                        api.logging().logToOutput("AI Auditor: " + providerFinal + " API key validation succeeded.");
                    } else {
                        setCloudApiValidationStatus(displayName + " validation failed — see Extension Errors for HTTP details.", Color.RED);
                        api.logging().raiseErrorEvent(providerFinal + " API key validation failed — check Extension Errors / Output for HTTP details.");
                        api.logging().logToOutput("AI Auditor: " + providerFinal + " API key validation failed.");
                    }
                    if (mainPanel != null) {
                        mainPanel.repaint();
                    }
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> {
                    setCloudApiValidationStatus(displayName + " validation error: " + t.getMessage(), Color.RED);
                    api.logging().logToError("AI Auditor: validation threw: " + t.getMessage());
                    if (mainPanel != null) {
                        mainPanel.repaint();
                    }
                });
            }
        });
    }
    

    private boolean performValidationRequest(String testEndpoint, String jsonBody, Map<String, String> headers) throws Exception {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(testEndpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(jsonBody.isEmpty() ? "GET" : "POST");
    
            // Set headers
            for (Map.Entry<String, String> header : headers.entrySet()) {
                conn.setRequestProperty(header.getKey(), header.getValue());
            }
    
            // Send body if applicable
            if (!jsonBody.isEmpty()) {
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
                }
            }
    
            // Log response for debugging
            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                String responseMessage = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))
                    .lines().reduce("", String::concat);
                throw new Exception("API error " + responseCode + ": " + responseMessage);
            }
    
            return true;
    
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }
    
    

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        
        // Create the main "AI Auditor" submenu
        JMenu aiAuditorMenu = new JMenu("AI Auditor");

        // Handle Message Editor selection
        event.messageEditorRequestResponse().ifPresent(editor -> {
            HttpRequestResponse reqRes = editor.requestResponse();
            if (reqRes == null || reqRes.request() == null) {
                return;
            }

            // Check for text selection using selectionOffsets
            Optional<Range> selectionRange = editor.selectionOffsets();
            if (selectionRange.isPresent()) {
                JMenuItem scanSelected = new JMenuItem("AI Auditor > Scan Selected Portion");
                scanSelected.addActionListener(e -> handleSelectedScan(editor));
                aiAuditorMenu.add(scanSelected);

                JMenuItem explainMeThis = new JMenuItem("AI Auditor > Explain me this");
                explainMeThis.addActionListener(e -> handleExplainMeThis(editor));
                aiAuditorMenu.add(explainMeThis);
            }

            // Add full scan option
            JMenuItem scanFull = new JMenuItem("AI Auditor > Scan Full Request/Response");
            scanFull.addActionListener(e -> handleFullScan(reqRes));
            aiAuditorMenu.add(scanFull);

            JMenuItem genPoc = new JMenuItem("AI Auditor > Investigate — PoC / exploitation (LLM)");
            genPoc.addActionListener(e -> handleGeneratePocFromTraffic(reqRes));
            aiAuditorMenu.add(genPoc);

            JMenuItem sendToChat = new JMenuItem("AI Auditor > Send to Chat");
            sendToChat.addActionListener(e -> attachTrafficToChat(reqRes, null));
            aiAuditorMenu.add(sendToChat);

            if (selectionRange.isPresent()) {
                JMenuItem sendSelectionToChat = new JMenuItem("AI Auditor > Send selection to Chat");
                sendSelectionToChat.addActionListener(e -> attachTrafficToChat(reqRes, extractSelectedEditorText(editor)));
                aiAuditorMenu.add(sendSelectionToChat);
            }
        });

        // Handle Proxy History / Site Map selection
        List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();
        if (!selectedItems.isEmpty()) {
            if (selectedItems.size() == 1) {
                HttpRequestResponse one = selectedItems.get(0);
                JMenuItem scanItem = new JMenuItem("Scan Request/Response");
                scanItem.addActionListener(e -> handleFullScan(one));
                aiAuditorMenu.add(scanItem);
                JMenuItem pocItem = new JMenuItem("Investigate — PoC / exploitation (LLM)");
                pocItem.addActionListener(e -> handleGeneratePocFromTraffic(one));
                aiAuditorMenu.add(pocItem);
                JMenuItem sendToChat = new JMenuItem("Send to Chat");
                sendToChat.addActionListener(e -> attachTrafficToChat(one, null));
                aiAuditorMenu.add(sendToChat);
            } else {
                JMenuItem scanMultiple = new JMenuItem(String.format("Scan %d Requests", selectedItems.size()));
                scanMultiple.addActionListener(e -> handleMultipleScan(selectedItems));
                aiAuditorMenu.add(scanMultiple);
                JMenuItem sendMultipleToChat = new JMenuItem(String.format("Send first of %d requests to Chat", selectedItems.size()));
                sendMultipleToChat.addActionListener(e -> attachTrafficToChat(selectedItems.get(0),
                        selectedItems.size() + " requests were selected; the first is attached."));
                aiAuditorMenu.add(sendMultipleToChat);
            }
        }

        List<AuditIssue> selectedIssues = getSelectedIssuesFromContextMenu(event);
        if (!selectedIssues.isEmpty()) {
            addAuditIssueMenuItems(aiAuditorMenu, selectedIssues);
        }
        
        // Only add the AI Auditor menu if it has sub-items
        if (aiAuditorMenu.getMenuComponentCount() > 0) {
            menuItems.add(aiAuditorMenu);
        }

        return menuItems;
    }

    /**
     * Burp invokes this when the user right-clicks in Target → Issues (and similar audit-issue views).
     * The generic {@link ContextMenuEvent} path does not receive issue selections from those views.
     */
    @Override
    public List<Component> provideMenuItems(AuditIssueContextMenuEvent event) {
        List<AuditIssue> selectedIssues = event.selectedIssues();
        if (selectedIssues == null || selectedIssues.isEmpty()) {
            return Collections.emptyList();
        }
        JMenu aiAuditorMenu = new JMenu("AI Auditor");
        addAuditIssueMenuItems(aiAuditorMenu, selectedIssues);
        return List.of(aiAuditorMenu);
    }

    private void addAuditIssueMenuItems(JMenu menu, List<AuditIssue> selectedIssues) {
        List<AuditIssue> issuesCopy = new ArrayList<>(selectedIssues);
        int count = selectedIssues.size();
        JMenuItem genPocIssues = new JMenuItem(count == 1
                ? "Investigate finding — PoC / exploitation (LLM)"
                : String.format("Investigate %d findings — PoC / exploitation (LLM)", count));
        genPocIssues.addActionListener(e -> handleScannerIssuesGeneratePoc(issuesCopy));
        menu.add(genPocIssues);

        JMenuItem deepDiveIssues = new JMenuItem(count == 1
                ? "Deep-dive finding — AI analysis (LLM)"
                : String.format("Deep-dive %d findings — AI analysis (LLM)", count));
        deepDiveIssues.addActionListener(e -> handleScannerIssuesDeepDive(issuesCopy));
        menu.add(deepDiveIssues);

        JMenuItem sendIssuesToChat = new JMenuItem(count == 1
                ? "Send finding to Chat"
                : String.format("Send %d findings to Chat", count));
        sendIssuesToChat.addActionListener(e -> attachIssuesToChat(issuesCopy));
        menu.add(sendIssuesToChat);
    }

    /**
     * Burp still exposes scanner-issue context through {@link ContextMenuEvent#selectedIssues()} (deprecated but
     * functional). Used as a fallback when issues are selected outside the dedicated audit-issue context menu.
     */
    @SuppressWarnings("deprecation")
    private static List<AuditIssue> getSelectedIssuesFromContextMenu(ContextMenuEvent event) {
        List<AuditIssue> issues = event.selectedIssues();
        return issues != null ? issues : Collections.emptyList();
    }

    /**
     * Resolves HTTP traffic for a Scanner issue: linked request/response pairs first, then site map lookup by base URL.
     */
    private List<HttpRequestResponse> resolveTrafficForIssue(AuditIssue issue) {
        if (issue == null) {
            return Collections.emptyList();
        }
        List<HttpRequestResponse> linked = issue.requestResponses();
        if (linked != null && !linked.isEmpty()) {
            List<HttpRequestResponse> valid = new ArrayList<>();
            for (HttpRequestResponse rr : linked) {
                if (rr != null && rr.request() != null) {
                    valid.add(rr);
                }
            }
            if (!valid.isEmpty()) {
                return valid;
            }
        }
        String baseUrl = issue.baseUrl();
        if (baseUrl != null && !baseUrl.isEmpty()) {
            try {
                List<HttpRequestResponse> fromSiteMap = api.siteMap().requestResponses(SiteMapFilter.prefixFilter(baseUrl));
                List<HttpRequestResponse> valid = new ArrayList<>();
                for (HttpRequestResponse rr : fromSiteMap) {
                    if (rr != null && rr.request() != null) {
                        valid.add(rr);
                    }
                }
                if (!valid.isEmpty()) {
                    log("Resolved " + valid.size() + " site map request(s) for issue \"" + issue.name()
                            + "\" via baseUrl " + baseUrl, LogCategory.GENERAL);
                    return valid;
                }
            } catch (Exception e) {
                log("Site map lookup failed for issue baseUrl " + baseUrl + ": " + e.getMessage(), LogCategory.GENERAL);
            }
        }
        return Collections.emptyList();
    }

    /**
     * Best-effort anchor for issues without linked messages (e.g. extension JS library findings).
     * Burp's Site Map rejects issues with null httpService and empty requestResponses.
     */
    private HttpRequestResponse resolveAnchorRequestResponse(AuditIssue issue) {
        if (issue == null) {
            return null;
        }
        List<HttpRequestResponse> rrs = resolveTrafficForIssue(issue);
        if (!rrs.isEmpty()) {
            return rrs.get(0);
        }
        String baseUrl = issue.baseUrl();
        if (baseUrl != null && !baseUrl.isEmpty()) {
            HttpRequestResponse fetched = fetchAnchorFromUrl(baseUrl);
            if (fetched != null) {
                return fetched;
            }
            int lastSlash = baseUrl.lastIndexOf('/');
            if (lastSlash > 8) {
                String parentPrefix = baseUrl.substring(0, lastSlash + 1);
                try {
                    for (HttpRequestResponse rr : api.siteMap().requestResponses(SiteMapFilter.prefixFilter(parentPrefix))) {
                        if (rr != null && rr.request() != null) {
                            log("Resolved anchor via parent prefix " + parentPrefix, LogCategory.GENERAL);
                            return rr;
                        }
                    }
                } catch (Exception e) {
                    log("Parent-prefix site map lookup failed for " + parentPrefix + ": " + e.getMessage(), LogCategory.GENERAL);
                }
            }
        }
        HttpService svc = issue.httpService();
        if (svc != null && baseUrl != null && !baseUrl.isEmpty()) {
            try {
                HttpRequest req = HttpRequest.httpRequest(svc, HttpRequest.httpRequestFromUrl(baseUrl).toString());
                return api.http().sendRequest(req);
            } catch (Exception e) {
                log("Anchor fetch with issue httpService failed: " + e.getMessage(), LogCategory.GENERAL);
            }
        }
        return null;
    }

    private HttpRequestResponse fetchAnchorFromUrl(String url) {
        try {
            HttpRequest req = HttpRequest.httpRequestFromUrl(url);
            HttpRequestResponse rr = api.http().sendRequest(req);
            if (rr != null && rr.request() != null) {
                log("Fetched anchor HTTP traffic for " + url, LogCategory.GENERAL);
                return rr;
            }
        } catch (Exception e) {
            log("Could not fetch anchor for " + url + ": " + e.getMessage(), LogCategory.GENERAL);
        }
        return null;
    }

    /**
     * Validates Premium Model for PoCs and API key before manual investigation. Returns resolved model id, or null.
     */
    private String validateManualInvestigationModelPreflight(String actionLabel) {
        String selectedModel = getManualInvestigationModel();
        if ("Default".equals(selectedModel)) {
            api.logging().raiseErrorEvent(
                    "AI Auditor: Premium Model for PoCs is \"Default\" and no provider could be inferred. "
                            + "On Connect: enter your xAI/Grok key, click Get Latest Models, pick xai/grok-… under "
                            + "Premium Model for PoCs, then Save Settings.");
            appendDashboardActivity(actionLabel + " blocked — no model configured");
            return null;
        }
        String[] modelParts = selectedModel.split("/", 2);
        String provider = modelParts.length == 2 ? modelParts[0] : "";
        if ("local".equals(provider)) {
            if (localEndpointField.getText().trim().isEmpty()) {
                api.logging().raiseErrorEvent("AI Auditor: Local LLM endpoint not configured.");
                appendDashboardActivity(actionLabel + " blocked — local endpoint missing");
                return null;
            }
        } else {
            String apiKey = getApiKeyForModel(selectedModel);
            if (apiKey == null || apiKey.isEmpty()) {
                String keyHint = "xai".equals(provider)
                        ? "AI Auditor: xAI (Grok) API key missing. Connect tab → enter key → Validate → Save Settings."
                        : "AI Auditor: API key not configured for " + selectedModel + ". Connect tab → Save Settings.";
                api.logging().raiseErrorEvent(keyHint);
                appendDashboardActivity(actionLabel + " blocked — API key missing for " + provider);
                return null;
            }
        }
        api.logging().raiseInfoEvent("AI Auditor: " + actionLabel + " using model " + selectedModel);
        return selectedModel;
    }

    private boolean isLocalLlmEndpointConfigured() {
        return localEndpointField != null && !localEndpointField.getText().trim().isEmpty();
    }

    private String normalizeLocalLlmBaseUrl() {
        String base = localEndpointField != null ? localEndpointField.getText().trim() : "";
        if (base.isEmpty()) {
            return "";
        }
        return base.replaceAll("/+$", "");
    }

    private static String stripLocalProviderPrefix(String id) {
        if (id == null) {
            return "";
        }
        String trimmed = id.trim();
        if (trimmed.regionMatches(true, 0, "local/", 0, 6)) {
            return trimmed.substring(6).trim();
        }
        return trimmed;
    }

    private boolean isLocalModelIdOnServer(String modelId, List<String> fromServer) {
        if (modelId == null || modelId.isEmpty() || fromServer == null || fromServer.isEmpty()) {
            return false;
        }
        String want = stripLocalProviderPrefix(modelId);
        for (String id : fromServer) {
            if (id != null && (want.equals(id) || want.equalsIgnoreCase(id))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Chat prefers the local LLM whenever a Local LLM URL is set; otherwise Premium Model for PoCs.
     */
    private String resolveChatModel() {
        if (isLocalLlmEndpointConfigured()) {
            String id = getDefaultLocalModelComboText();
            if (id != null && !id.isEmpty() && !id.equalsIgnoreCase(LEGACY_LOCAL_MODEL_PLACEHOLDER)) {
                return id.startsWith("local/") ? id : "local/" + id;
            }
            String auto = getAutomaticAuditModel();
            if (auto != null && auto.startsWith("local/") && auto.length() > "local/".length()) {
                return auto;
            }
            return cachedDefaultLocal != null && !cachedDefaultLocal.isEmpty()
                    ? cachedDefaultLocal
                    : "local/gemma4:e4b";
        }
        return getManualInvestigationModel();
    }

    private String validateChatModelPreflight() {
        String selectedModel = resolveChatModel();
        if (selectedModel == null || selectedModel.trim().isEmpty() || "Default".equals(selectedModel)) {
            api.logging().raiseErrorEvent(
                    "AI Auditor Chat: no model available. Set Local LLM URL and Local LLM model id on Connect, "
                            + "or pick Premium Model for PoCs as a cloud fallback, then Save Settings.");
            appendDashboardActivity("Chat blocked — no local LLM or premium model configured");
            return null;
        }
        String[] modelParts = selectedModel.split("/", 2);
        String provider = modelParts.length == 2 ? modelParts[0] : "";
        if ("local".equals(provider)) {
            if (!isLocalLlmEndpointConfigured()) {
                api.logging().raiseErrorEvent("AI Auditor Chat: Local LLM URL is empty.");
                appendDashboardActivity("Chat blocked — local endpoint missing");
                return null;
            }
        } else {
            String apiKey = getApiKeyForModel(selectedModel);
            if (apiKey == null || apiKey.isEmpty()) {
                api.logging().raiseErrorEvent(
                        "AI Auditor Chat: no local LLM configured, and API key missing for fallback model "
                                + selectedModel + ". Connect tab → Local LLM URL or cloud key → Save Settings.");
                appendDashboardActivity("Chat blocked — API key missing for " + provider);
                return null;
            }
        }
        api.logging().raiseInfoEvent("AI Auditor: Chat using model " + selectedModel);
        return selectedModel;
    }

    private String buildScannerIssueDeepDivePreamble(AuditIssue issue) {
        StringBuilder sb = new StringBuilder();
        sb.append("CONTEXT: Burp (or another extension such as HTTP Request Smuggler) already reported an issue below.\n");
        sb.append("Analyze in light of that finding. Summarize impact in plain language; say whether the evidence supports ");
        sb.append("a real vulnerability (e.g. desync / smuggling / cache poisoning) versus a false positive; ");
        sb.append("give concrete verification steps in Burp Repeater and what to log or compare; ");
        sb.append("note parser differential or tunneling angles when relevant.\n");
        sb.append("Use the JSON findings structure from the main instructions for any distinct NEW issues you add; ");
        sb.append("you may reference the existing Burp issue in explanations.\n\n");
        sb.append("=== EXISTING BURP ISSUE ===\n");
        sb.append("Name: ").append(issue.name()).append("\n");
        sb.append("Severity: ").append(issue.severity()).append("\n");
        sb.append("Confidence: ").append(issue.confidence()).append("\n");
        String rem = issue.remediation();
        if (rem != null && !rem.isEmpty()) {
            sb.append("Remediation: ").append(rem).append("\n");
        }
        sb.append("Detail:\n").append(issue.detail()).append("\n");
        return sb.toString();
    }

    private void handleScannerIssuesDeepDive(List<AuditIssue> issues) {
        if (issues == null || issues.isEmpty()) {
            api.logging().raiseInfoEvent("AI Auditor: Deep-dive requested but no issues were selected.");
            return;
        }
        api.logging().raiseInfoEvent("AI Auditor: starting deep-dive analysis for " + issues.size() + " issue(s)…");
        appendDashboardActivity("Deep-dive requested — " + issues.size() + " issue(s)");
        String model = validateManualInvestigationModelPreflight("Deep-dive");
        if (model == null) {
            return;
        }
        int queued = 0;
        int metadataOnly = 0;
        for (AuditIssue issue : issues) {
            String preamble = buildScannerIssueDeepDivePreamble(issue);
            List<HttpRequestResponse> rrs = resolveTrafficForIssue(issue);
            if (rrs.isEmpty()) {
                log("Deep-dive: issue \"" + issue.name() + "\" has no linked HTTP messages; running metadata-only analysis.",
                        LogCategory.GENERAL);
                api.logging().raiseInfoEvent(
                        "AI Auditor: issue \"" + truncateForIssueTitle(issue.name(), 80)
                                + "\" has no stored HTTP traffic — deep-dive will use issue metadata only.");
                processAuditRequest(null, null, false, preamble, false);
                queued++;
                metadataOnly++;
                continue;
            }
            for (HttpRequestResponse rr : rrs) {
                processAuditRequest(rr, null, false, preamble, false);
                queued++;
            }
        }
        if (queued == 0) {
            api.logging().raiseInfoEvent(
                    "AI Auditor: Could not queue deep-dive for the selected issue(s). Check Connect tab model and API key.");
        } else {
            log("Deep-dive queued " + queued + " AI audit run(s) for Scanner issue(s)"
                    + (metadataOnly > 0 ? " (" + metadataOnly + " metadata-only)" : "") + ".", LogCategory.GENERAL);
            appendDashboardActivity("Scanner issue deep-dive queued — " + queued + " AI audit run(s)");
        }
    }

    private String buildScannerIssuePocContext(AuditIssue issue) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== BURP / SCANNER FINDING (use as context; verify independently) ===\n");
        sb.append("Title: ").append(issue.name()).append("\n");
        sb.append("Severity: ").append(issue.severity()).append("\n");
        sb.append("Confidence: ").append(issue.confidence()).append("\n");
        String rem = issue.remediation();
        if (rem != null && !rem.isEmpty()) {
            sb.append("Remediation hint: ").append(rem).append("\n");
        }
        sb.append("Detail:\n").append(issue.detail()).append("\n");
        return sb.toString();
    }

    private static String truncateForIssueTitle(String s, int maxLen) {
        if (s == null) {
            return "";
        }
        String t = s.trim().replaceAll("\\s+", " ");
        return t.length() <= maxLen ? t : t.substring(0, maxLen - 1) + "…";
    }

    private String trimPocEvidenceForPrompt(String evidenceBlock, String findingName) {
        if (evidenceBlock == null || evidenceBlock.isEmpty()) {
            return "";
        }
        int estimatedTokens = RequestChunker.estimateTokens(evidenceBlock);
        int configuredCap = maxChunkSize > 0 ? maxChunkSize : POC_PROMPT_HARD_CAP_TOKENS;
        int targetEvidenceTokens = Math.max(
                POC_PROMPT_MIN_EVIDENCE_TOKENS,
                Math.min(configuredCap, POC_PROMPT_HARD_CAP_TOKENS));

        if (estimatedTokens <= targetEvidenceTokens) {
            return evidenceBlock;
        }

        int maxChars = Math.max(4096, targetEvidenceTokens * 4);
        String trimmed = trimEvidenceBySection(evidenceBlock, maxChars);
        int trimmedTokens = RequestChunker.estimateTokens(trimmed);

        log(String.format(
                "PoC evidence trimmed for \"%s\" from ~%d tokens to ~%d tokens (cap=%d).",
                truncateForIssueTitle(findingName, 100),
                estimatedTokens,
                trimmedTokens,
                targetEvidenceTokens), LogCategory.TOKEN_INFO);
        appendDashboardActivity(String.format(
                "PoC evidence trimmed — %s (~%d tokens -> ~%d)",
                truncateForIssueTitle(findingName, 90),
                estimatedTokens,
                trimmedTokens));
        return trimmed;
    }

    private String trimEvidenceBySection(String evidence, int maxChars) {
        if (evidence == null || evidence.length() <= maxChars) {
            return evidence;
        }

        String scannerTrafficMarker = "\n\n=== HTTP traffic (request then response) ===\n\n";
        int scannerIdx = evidence.indexOf(scannerTrafficMarker);
        if (scannerIdx >= 0) {
            String prefix = evidence.substring(0, scannerIdx + scannerTrafficMarker.length());
            int budget = Math.max(512, maxChars - prefix.length());
            return prefix + trimTrafficRequestFirst(evidence.substring(scannerIdx + scannerTrafficMarker.length()), budget);
        }

        String responseMarker = "\n\n=== HTTP response ===\n";
        int responseIdx = evidence.indexOf(responseMarker);
        if (responseIdx >= 0) {
            String prefix = evidence.substring(0, responseIdx + responseMarker.length());
            int budget = Math.max(512, maxChars - prefix.length());
            return prefix + truncateMiddleWithNotice(evidence.substring(responseIdx + responseMarker.length()), budget);
        }

        return truncateMiddleWithNotice(evidence, maxChars);
    }

    private String trimTrafficRequestFirst(String traffic, int budget) {
        if (traffic == null || traffic.length() <= budget) {
            return traffic;
        }
        int responseStart = traffic.indexOf("\n\nHTTP/");
        if (responseStart <= 0) {
            return truncateMiddleWithNotice(traffic, budget);
        }

        String requestPart = traffic.substring(0, responseStart);
        String responsePart = traffic.substring(responseStart);
        if (requestPart.length() >= budget) {
            return truncateMiddleWithNotice(requestPart, budget);
        }

        int responseBudget = Math.max(256, budget - requestPart.length());
        return requestPart + truncateMiddleWithNotice(responsePart, responseBudget);
    }

    private String truncateMiddleWithNotice(String text, int maxChars) {
        if (text == null || text.length() <= maxChars) {
            return text;
        }
        if (maxChars <= 128) {
            return text.substring(0, maxChars);
        }
        String notice = "\n\n... [truncated by AI Auditor to fit model prompt limits] ...\n\n";
        if (notice.length() >= maxChars) {
            return text.substring(0, maxChars);
        }
        int bodyBudget = maxChars - notice.length();
        int headLen = (bodyBudget * 2) / 3;
        int tailLen = bodyBudget - headLen;
        return text.substring(0, headLen) + notice + text.substring(text.length() - tailLen);
    }

    private void handleScannerIssuesGeneratePoc(List<AuditIssue> issues) {
        if (issues == null || issues.isEmpty()) {
            api.logging().raiseInfoEvent("AI Auditor: PoC investigation requested but no issues were selected.");
            return;
        }
        api.logging().raiseInfoEvent("AI Auditor: starting PoC investigation for " + issues.size() + " issue(s)…");
        appendDashboardActivity("PoC investigation requested — " + issues.size() + " issue(s)");
        if (validateManualInvestigationModelPreflight("PoC investigation") == null) {
            return;
        }
        int queued = 0;
        int metadataOnly = 0;
        for (AuditIssue issue : issues) {
            String issueCtx = buildScannerIssuePocContext(issue);
            List<HttpRequestResponse> rrs = resolveTrafficForIssue(issue);
            if (rrs.isEmpty()) {
                HttpRequestResponse anchor = resolveAnchorRequestResponse(issue);
                String evidence;
                if (anchor != null && anchor.request() != null) {
                    String traffic = anchor.request().toString()
                            + "\n\n"
                            + (anchor.response() != null ? anchor.response().toString() : "(no response captured)");
                    evidence = issueCtx + "\n\n=== HTTP traffic (anchor fetch for asset URL) ===\n\n" + traffic;
                    log("Generate PoC: anchored issue \"" + issue.name() + "\" via asset URL fetch.", LogCategory.GENERAL);
                } else {
                    log("Generate PoC: issue \"" + issue.name() + "\" has no linked HTTP messages; running metadata-only investigation.",
                            LogCategory.GENERAL);
                    api.logging().raiseInfoEvent(
                            "AI Auditor: issue \"" + truncateForIssueTitle(issue.name(), 80)
                                    + "\" has no stored HTTP traffic — PoC will use issue metadata only.");
                    evidence = issueCtx + "\n\n[NOTE: No HTTP traffic was linked to this issue. "
                            + "Analysis is based on issue metadata only — verification steps may be limited.]";
                }
                String title = "AI investigate / PoC: " + truncateForIssueTitle(issue.name(), 100);
                runPocAsync(anchor, evidence, title, true, issue);
                queued++;
                if (anchor == null) {
                    metadataOnly++;
                }
                continue;
            }
            for (HttpRequestResponse rr : rrs) {
                String traffic = rr.request().toString()
                        + "\n\n"
                        + (rr.response() != null ? rr.response().toString() : "(no response captured)");
                String evidence = issueCtx + "\n\n=== HTTP traffic (request then response) ===\n\n" + traffic;
                String title = "AI investigate / PoC: " + truncateForIssueTitle(issue.name(), 100);
                runPocAsync(rr, evidence, title, true, issue);
                queued++;
            }
        }
        if (queued == 0) {
            api.logging().raiseInfoEvent(
                    "AI Auditor: Could not queue PoC for the selected issue(s). Check Connect tab model and API key.");
        } else {
            log("Generate PoC queued " + queued + " LLM run(s)"
                    + (metadataOnly > 0 ? " (" + metadataOnly + " metadata-only)" : "") + ".", LogCategory.GENERAL);
            appendDashboardActivity("PoC generation queued — " + queued + " LLM run(s) from Scanner issue(s)");
        }
    }

    private void handleGeneratePocFromTraffic(HttpRequestResponse rr) {
        if (rr == null || rr.request() == null) {
            return;
        }
        String evidence = "=== HTTP request ===\n"
                + rr.request().toString()
                + "\n\n=== HTTP response ===\n"
                + (rr.response() != null ? rr.response().toString() : "(no response captured)");
        runPocAsync(rr, evidence, "AI investigate / PoC notes", true, null);
    }

    /**
     * Single LLM call with the PoC prompt only (no JSON-finding template merge).
     * When {@code addAsNewIssue} is false, the result is logged for review instead of creating a new Site Map issue.
     */
    private void runPocAsync(HttpRequestResponse rr, String evidenceBlock, String issueName, boolean addAsNewIssue, AuditIssue sourceIssueForReplacement) {
        String selectedModel = validateManualInvestigationModelPreflight("PoC / investigation");
        if (selectedModel == null) {
            return;
        }
        String apiKey = getApiKeyForModel(selectedModel);

        String instructions = pocPromptArea != null ? pocPromptArea.getText() : null;
        if (instructions == null || instructions.trim().isEmpty()) {
            instructions = getDefaultPocPrompt();
        }
        String boundedEvidence = trimPocEvidenceForPrompt(evidenceBlock, issueName);
        final String fullUserMessage = instructions + "\n\n--- Evidence ---\n\n" + boundedEvidence;
        final String model = selectedModel;
        final String key = apiKey;
        final HttpRequestResponse reqRes = rr;
        final String findingName = issueName;
        final boolean shouldAddIssue = addAsNewIssue;
        final AuditIssue replacementSourceIssue = sourceIssueForReplacement;

        appendDashboardActivity("PoC / investigation started — " + model + " — " + truncateForIssueTitle(findingName, 120));
        final ScheduledFuture<?> pocHeartbeat = startPocHeartbeat(model, findingName);

        CompletableFuture.supplyAsync(() -> {
            try {
                return sendToAI(model, key, fullUserMessage, false);
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }, threadPoolManager.getExecutor()).thenAccept(aiResponse -> {
            stopHeartbeat(pocHeartbeat);
            String text;
            try {
                text = extractContentFromResponse(aiResponse, model);
            } catch (Exception e) {
                text = "";
            }
            if (text == null || text.isEmpty()) {
                text = "(No text extracted from model response. Check Extension output / logging level for raw API output.)";
            }
            boolean likelyFalsePositive = looksLikeFalsePositiveVerdict(text);
            PocAutoExecutionResult execResult = likelyFalsePositive
                    ? PocAutoExecutionResult.skipped("investigation text suggests a possible false positive")
                    : executeGeneratedPocRequests(text, reqRes);
            String autoExecutionSummary = execResult.toMarkdownSummary();
            String verificationSection = "";
            if (!likelyFalsePositive && execResult.hasResponseBodies()) {
                appendDashboardActivity("PoC verification — analyzing HTTP response bodies…");
                try {
                    String verification = verifyPocExecutionsWithModel(text, execResult, model, key);
                    if (verification != null && !verification.trim().isEmpty()) {
                        verificationSection = "\n\n---\n\n## PoC response verification (live traffic)\n\n" + verification.trim();
                    }
                } catch (Exception verifyEx) {
                    verificationSection = "\n\n---\n\n## PoC response verification (live traffic)\n\n"
                            + "Verification call failed: " + verifyEx.getMessage();
                    log("PoC response verification failed: " + verifyEx.getMessage(), LogCategory.GENERAL);
                }
            }
            String detail = "**AI investigation (PoC / exploitation)** — same *intent* as Burp’s built-in “dig into finding”; you chose the model. Models can be wrong.\n\n"
                    + text + autoExecutionSummary + verificationSection;
            if (shouldAddIssue) {
                String finalIssueName = findingName;
                AuditIssueSeverity finalSeverity = AuditIssueSeverity.INFORMATION;
                AuditIssueConfidence finalConfidence = AuditIssueConfidence.TENTATIVE;
                if (replacementSourceIssue != null) {
                    // Keep the same issue identity so consolidation can replace the previous entry.
                    finalIssueName = replacementSourceIssue.name();
                    if (replacementSourceIssue.severity() != null) {
                        finalSeverity = replacementSourceIssue.severity();
                    }
                    if (replacementSourceIssue.confidence() != null) {
                        finalConfidence = replacementSourceIssue.confidence();
                    }
                    if (likelyFalsePositive) {
                        detail = "**Model note (not definitive):** One investigation suggests a possible false positive. "
                                + "Another model or manual testing may disagree — do not downgrade the finding from prose alone.\n\n"
                                + detail;
                    }
                }
                HttpRequestResponse anchorRr = reqRes;
                if ((anchorRr == null || anchorRr.request() == null) && replacementSourceIssue != null) {
                    anchorRr = resolveAnchorRequestResponse(replacementSourceIssue);
                }
                String endpoint;
                List<HttpRequestResponse> issueRrs;
                if (anchorRr != null && anchorRr.request() != null) {
                    endpoint = anchorRr.request().url().toString();
                    issueRrs = Collections.singletonList(anchorRr);
                } else if (replacementSourceIssue != null && replacementSourceIssue.baseUrl() != null) {
                    endpoint = replacementSourceIssue.baseUrl();
                    issueRrs = Collections.emptyList();
                } else {
                    endpoint = "unknown";
                    issueRrs = Collections.emptyList();
                }
                if (issueRrs.isEmpty()) {
                    api.logging().logToOutput("AI Auditor investigation result for \"" + finalIssueName + "\":\n" + detail);
                    api.logging().raiseInfoEvent(
                            "AI Auditor: PoC complete — no HTTP anchor for Site Map. Full result is in Extension Output.");
                    appendDashboardActivity("PoC / investigation finished — result in Extension Output (no HTTP anchor)");
                    return;
                }
                AIAuditIssue issue = new AIAuditIssue.Builder()
                        .name(finalIssueName)
                        .detail(detail)
                        .endpoint(endpoint)
                        .severity(finalSeverity)
                        .confidence(finalConfidence)
                        .requestResponses(issueRrs)
                        .modelUsed(model)
                        .build();
                try {
                    api.siteMap().add(issue);
                    log("PoC / exploitation notes added to Site Map.", LogCategory.GENERAL);
                    appendDashboardActivity("PoC / investigation finished — notes added to Site Map");
                } catch (Exception addEx) {
                    api.logging().logToOutput("AI Auditor investigation result for \"" + finalIssueName + "\":\n" + detail);
                    showError("PoC notes could not be added to Site Map; result saved to Extension Output", addEx);
                    appendDashboardActivity("PoC / investigation finished — Site Map add failed; see Extension Output");
                }
            } else {
                log("PoC / exploitation notes generated (no issue creation): "
                        + truncateForIssueTitle(findingName, 120), LogCategory.GENERAL);
                api.logging().logToOutput("AI Auditor investigation result for \"" + findingName + "\":\n" + detail);
                appendDashboardActivity("PoC / investigation finished — result generated in Extension Output");
            }
        }).exceptionally(ex -> {
            stopHeartbeat(pocHeartbeat);
            Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
            appendDashboardActivity("PoC / investigation failed — " + formatExceptionChainForDashboard(cause));
            showError("PoC generation failed", cause);
            return null;
        });
    }

    /**
     * Dashboard one-liner: include nested causes so "Failed after N attempts" is not shown without the root API error.
     */
    private String formatExceptionChainForDashboard(Throwable t) {
        if (t == null) {
            return "unknown error";
        }
        while (t instanceof CompletionException && t.getCause() != null) {
            t = t.getCause();
        }
        List<String> parts = new ArrayList<>();
        Throwable cur = t;
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        while (cur != null && seen.size() < 8) {
            if (!seen.add(cur)) {
                break;
            }
            String msg = cur.getMessage();
            if (msg != null && !msg.trim().isEmpty()) {
                String oneLine = msg.replace('\n', ' ').trim();
                if (!parts.contains(oneLine)) {
                    parts.add(oneLine);
                }
            }
            Throwable next = cur.getCause();
            if (next == cur) {
                break;
            }
            cur = next;
        }
        if (parts.isEmpty()) {
            return t.getClass().getSimpleName();
        }
        String joined = String.join(" — ", parts);
        int cap = 900;
        return joined.length() > cap ? joined.substring(0, cap) + "…" : joined;
    }

    private boolean looksLikeFalsePositiveVerdict(String text) {
        if (text == null) {
            return false;
        }
        String t = text.toLowerCase(Locale.ROOT);
        return t.contains("likely false positive")
                || t.contains("likely a false positive")
                || t.contains("false positive verdict")
                || t.contains("probably a false positive");
    }

    private static final class PocExecutionRecord {
        final int index;
        final String requestFirstLine;
        final boolean sent;
        final String sendError;
        final int statusCode;
        final String contentType;
        final int responseBodyLength;
        final String responseBodyPreview;
        final List<String> heuristicHits;

        PocExecutionRecord(int index, String requestFirstLine, boolean sent, String sendError,
                int statusCode, String contentType, int responseBodyLength, String responseBodyPreview,
                List<String> heuristicHits) {
            this.index = index;
            this.requestFirstLine = requestFirstLine;
            this.sent = sent;
            this.sendError = sendError;
            this.statusCode = statusCode;
            this.contentType = contentType;
            this.responseBodyLength = responseBodyLength;
            this.responseBodyPreview = responseBodyPreview;
            this.heuristicHits = heuristicHits != null ? heuristicHits : Collections.emptyList();
        }
    }

    private static final class PocAutoExecutionResult {
        final List<PocExecutionRecord> records;
        final String skipReason;

        private PocAutoExecutionResult(List<PocExecutionRecord> records, String skipReason) {
            this.records = records != null ? records : Collections.emptyList();
            this.skipReason = skipReason;
        }

        static PocAutoExecutionResult skipped(String reason) {
            return new PocAutoExecutionResult(Collections.emptyList(), reason);
        }

        boolean hasResponseBodies() {
            for (PocExecutionRecord r : records) {
                if (r.sent && r.responseBodyPreview != null && !r.responseBodyPreview.isEmpty()) {
                    return true;
                }
            }
            return false;
        }

        String toMarkdownSummary() {
            if (skipReason != null && !skipReason.isEmpty()) {
                return "\n\n---\nAuto-execution skipped: " + skipReason
                        + " (verify with another model or manual PoC before closing).";
            }
            if (records.isEmpty()) {
                return "\n\n---\nAuto-execution: No parseable raw HTTP requests found in the PoC output.";
            }
            StringBuilder sb = new StringBuilder("\n\n---\nAuto-execution summary:\n");
            int sent = 0;
            for (PocExecutionRecord r : records) {
                if (r.sent) {
                    sent++;
                }
                if (!r.sent) {
                    sb.append(String.format("- Request %d: failed to send (%s).\n", r.index, r.sendError));
                    continue;
                }
                sb.append(String.format("- Request %d (%s): HTTP %d", r.index, r.requestFirstLine, r.statusCode));
                if (r.contentType != null && !r.contentType.isEmpty()) {
                    sb.append(", Content-Type: ").append(r.contentType);
                }
                sb.append(String.format(", body length: %d bytes.\n", r.responseBodyLength));
                if (!r.heuristicHits.isEmpty()) {
                    sb.append("  Heuristic signals: ").append(String.join("; ", r.heuristicHits)).append("\n");
                }
                if (r.responseBodyPreview != null && !r.responseBodyPreview.isEmpty()) {
                    sb.append("  Body preview:\n```\n").append(r.responseBodyPreview).append("\n```\n");
                }
            }
            sb.append(String.format("Sent %d/%d request(s).", sent, records.size()));
            return sb.toString();
        }

        String toVerificationEvidenceBlock(int maxTotalChars) {
            StringBuilder sb = new StringBuilder();
            int budget = maxTotalChars;
            for (PocExecutionRecord r : records) {
                if (!r.sent) {
                    continue;
                }
                String block = formatRecordForVerification(r);
                if (block.length() > budget) {
                    if (budget > 256) {
                        sb.append(block, 0, budget).append("\n... [truncated for verification prompt] ...\n");
                    }
                    break;
                }
                sb.append(block);
                budget -= block.length();
            }
            return sb.toString();
        }

        private static String formatRecordForVerification(PocExecutionRecord r) {
            StringBuilder sb = new StringBuilder();
            sb.append("### Request ").append(r.index).append(": ").append(r.requestFirstLine).append("\n");
            sb.append("Status: ").append(r.statusCode).append("\n");
            if (r.contentType != null && !r.contentType.isEmpty()) {
                sb.append("Content-Type: ").append(r.contentType).append("\n");
            }
            sb.append("Body length: ").append(r.responseBodyLength).append(" bytes\n");
            if (!r.heuristicHits.isEmpty()) {
                sb.append("Heuristic signals: ").append(String.join("; ", r.heuristicHits)).append("\n");
            }
            if (r.responseBodyPreview != null && !r.responseBodyPreview.isEmpty()) {
                sb.append("Response body preview:\n").append(r.responseBodyPreview).append("\n");
            }
            sb.append("\n");
            return sb.toString();
        }
    }

    private PocAutoExecutionResult executeGeneratedPocRequests(String aiText, HttpRequestResponse sourceRequestResponse) {
        List<String> requests = extractHttpRequestsFromMarkdown(aiText);
        if (requests.isEmpty()) {
            return new PocAutoExecutionResult(Collections.emptyList(), null);
        }

        int cap = Math.min(MAX_AUTO_POC_REQUESTS, requests.size());
        List<PocExecutionRecord> records = new ArrayList<>();
        HttpService fallbackService = sourceRequestResponse != null && sourceRequestResponse.request() != null
                ? sourceRequestResponse.request().httpService()
                : null;
        for (int i = 0; i < cap; i++) {
            String rawRequest = requests.get(i);
            String firstLine = rawRequest.lines().findFirst().orElse("(unknown request)");
            try {
                HttpRequest req = HttpRequest.httpRequest(rawRequest);
                if ((req.httpService() == null || req.httpService().host() == null || req.httpService().host().isEmpty())
                        && fallbackService != null) {
                    req = HttpRequest.httpRequest(fallbackService, rawRequest);
                }
                HttpRequestResponse rr = api.http().sendRequest(req);
                HttpResponse resp = rr != null ? rr.response() : null;
                int status = resp != null ? resp.statusCode() : -1;
                String contentType = extractResponseContentType(resp);
                String body = resp != null ? resp.bodyToString() : "";
                int bodyLen = body != null ? body.length() : 0;
                String preview = body != null && !body.isEmpty()
                        ? truncateMiddleWithNotice(body, POC_RESPONSE_BODY_PREVIEW_CHARS)
                        : "";
                List<String> hits = analyzePocResponseHeuristics(rawRequest, body, status);
                records.add(new PocExecutionRecord(i + 1, firstLine, true, null, status, contentType, bodyLen, preview, hits));
            } catch (Exception e) {
                records.add(new PocExecutionRecord(i + 1, firstLine, false, e.getMessage(), -1, null, 0, "", Collections.emptyList()));
            }
        }
        if (requests.size() > cap) {
            log(String.format("Auto-execution: %d additional request(s) ignored due to cap (%d).",
                    requests.size() - cap, MAX_AUTO_POC_REQUESTS), LogCategory.GENERAL);
        }
        return new PocAutoExecutionResult(records, null);
    }

    private static String extractResponseContentType(HttpResponse resp) {
        if (resp == null) {
            return "";
        }
        for (HttpHeader h : resp.headers()) {
            if (h != null && "Content-Type".equalsIgnoreCase(h.name())) {
                return h.value();
            }
        }
        return "";
    }

    private List<String> analyzePocResponseHeuristics(String rawRequest, String responseBody, int statusCode) {
        List<String> hits = new ArrayList<>();
        if (responseBody == null || responseBody.isEmpty()) {
            if (statusCode > 0) {
                hits.add("empty response body");
            }
            return hits;
        }
        String bodyLower = responseBody.toLowerCase(Locale.ROOT);
        if (bodyLower.contains("<script")) {
            hits.add("<script tag present in response body");
        }
        if (bodyLower.contains("javascript:")) {
            hits.add("javascript: URI present in response body");
        }
        if (bodyLower.contains("onerror=") || bodyLower.contains("onload=")) {
            hits.add("inline event handler attribute present");
        }
        List<String> reflected = findReflectedPayloadFragments(rawRequest, responseBody);
        for (String fragment : reflected) {
            hits.add("request fragment reflected in body: \"" + truncateForIssueTitle(fragment, 80) + "\"");
        }
        return hits;
    }

    private List<String> findReflectedPayloadFragments(String rawRequest, String responseBody) {
        List<String> reflected = new ArrayList<>();
        if (rawRequest == null || responseBody == null || responseBody.isEmpty()) {
            return reflected;
        }
        Set<String> candidates = new LinkedHashSet<>();
        Matcher urlParam = Pattern.compile("[?&]([^=&]{4,})=").matcher(rawRequest);
        while (urlParam.find()) {
            candidates.add(urlParam.group(1));
        }
        Matcher urlValue = Pattern.compile("[?&][^=]+=([^&\\s\\r\\n]{4,})").matcher(rawRequest);
        while (urlValue.find()) {
            try {
                candidates.add(java.net.URLDecoder.decode(urlValue.group(1), StandardCharsets.UTF_8));
            } catch (Exception e) {
                candidates.add(urlValue.group(1));
            }
        }
        int bodyStart = rawRequest.indexOf("\r\n\r\n");
        if (bodyStart < 0) {
            bodyStart = rawRequest.indexOf("\n\n");
        }
        if (bodyStart >= 0 && bodyStart + 4 < rawRequest.length()) {
            String reqBody = rawRequest.substring(bodyStart).trim();
            if (reqBody.length() >= 4 && reqBody.length() <= 512) {
                candidates.add(reqBody);
            }
        }
        for (String c : candidates) {
            if (c.length() >= 4 && responseBody.contains(c) && reflected.size() < 5) {
                reflected.add(c);
            }
        }
        return reflected;
    }

    private String verifyPocExecutionsWithModel(String pocProposalText, PocAutoExecutionResult execution,
            String model, String apiKey) throws Exception {
        String evidence = execution.toVerificationEvidenceBlock(POC_VERIFY_TOTAL_RESPONSE_CHARS);
        if (evidence.isEmpty()) {
            return "";
        }
        String prompt = "You previously proposed a penetration-test PoC. The operator executed your raw HTTP request(s) through Burp. "
                + "Using YOUR proposed success criteria (especially section 3 — what to observe) and the ACTUAL responses below, "
                + "decide whether the exploit/PoC is working.\n\n"
                + "OUTPUT — Markdown only:\n"
                + "## Verdict\n"
                + "One of: **CONFIRMED** | **LIKELY** | **INCONCLUSIVE** | **NOT_WORKING**\n\n"
                + "## Evidence from responses\n"
                + "- Quote specific substrings, headers, or status/length deltas from the live responses.\n"
                + "- For XSS/script injection: state clearly whether a script or payload appears in the HTML/JS response (and where).\n"
                + "- For SQLi/command injection: cite error strings, timing, or content changes.\n\n"
                + "## Next step\n"
                + "If not confirmed: one concrete next request or capture to try.\n\n"
                + "---\n## Your proposed PoC\n\n"
                + pocProposalText
                + "\n\n---\n## Live execution results\n\n"
                + evidence;
        JSONObject resp = sendToAI(model, apiKey, prompt, false);
        return extractContentFromResponse(resp, model);
    }

    private List<String> extractHttpRequestsFromMarkdown(String text) {
        List<String> requests = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return requests;
        }
        Pattern fencePattern = Pattern.compile("```(?:http)?\\s*\\n(.*?)\\n```", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        Matcher matcher = fencePattern.matcher(text);
        while (matcher.find()) {
            String block = matcher.group(1).trim();
            if (looksLikeRawHttpRequest(block)) {
                requests.add(block);
            }
        }
        return requests;
    }

    private boolean looksLikeRawHttpRequest(String block) {
        if (block == null || block.isEmpty()) {
            return false;
        }
        int lineEnd = block.indexOf('\n');
        String firstLine = (lineEnd >= 0 ? block.substring(0, lineEnd) : block).trim();
        return firstLine.matches("^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\\s+\\S+\\s+HTTP/\\d\\.\\d$");
    }

    private void handleExplainMeThis(MessageEditorHttpRequestResponse editor) {
        try {
            Optional<Range> selectionRange = editor.selectionOffsets();
            if (!selectionRange.isPresent()) {
                return;
            }

            int start = selectionRange.get().startIndexInclusive();
            int end = selectionRange.get().endIndexExclusive();

            String editorContent = editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST
                    ? editor.requestResponse().request().toString()
                    : editor.requestResponse().response() != null ? editor.requestResponse().response().toString() : "";

            if (start >= 0 && end <= editorContent.length()) {
                String selectedText = editorContent.substring(start, end);
                
                String customPrompt = explainMeThisPromptArea.getText();
				
				String prompt = (customPrompt != null && !customPrompt.isEmpty())
						? customPrompt
						: getDefaultExplainMeThisPrompt();
				log("ExplainMeThis Final Prompt=" + prompt);

                String inputForAI;
                if (selectedText.length() > 100) {
					inputForAI = selectedText.substring(0, 50)
						+ "..."
						+ selectedText.substring(selectedText.length() - 50);
                } else {
                    inputForAI = selectedText;
                }

                // Send to AI in a background thread
                String finalPrompt = prompt;
                String finalSelectedText = selectedText;
                String finalInputForAI = inputForAI; // Capture for use in lambda
                HttpRequestResponse finalReqRes = editor.requestResponse(); // Capture for use in lambda
                final String investigationModel = getManualInvestigationModel();

                CompletableFuture.supplyAsync(() -> {
                    try {
                        JSONObject aiResponse = sendToAI(investigationModel, getApiKeyForModel(investigationModel), finalPrompt + "\n\nContent to explain:\n" + finalSelectedText);
                        return extractContentFromResponse(aiResponse, investigationModel);
                    } catch (Exception e) {
                        api.logging().logToError("Error explaining content: " + e.getMessage());
                        return "Error: " + e.getMessage();
                    }
                }, threadPoolManager.getExecutor()).thenAccept(aiExplanation -> {
                    // Create a Burp finding
					String issueName = "AI Explanation: Generated by 'AI Auditor - Explain me this' feature";
                    StringBuilder issueDetail = new StringBuilder();
                    issueDetail.append(" **Input (Selected Content):**\n").append(finalSelectedText).append("\n\n");
                    issueDetail.append("\n **AI Explanation:** \n").append(aiExplanation);

                    AIAuditIssue issue = new AIAuditIssue.Builder()
                            .name(issueName)
                            .detail(issueDetail.toString())
                            .endpoint(finalReqRes.request().url().toString())
                            .severity(AuditIssueSeverity.INFORMATION)
                            .confidence(AuditIssueConfidence.CERTAIN)
                            .requestResponses(Collections.singletonList(finalReqRes))
                            .modelUsed(investigationModel)
                            .build();							
                    api.siteMap().add(issue);
                    log("'Explain me this' result added to Site Map as an informational finding.", LogCategory.GENERAL);
                });

            } else {
                throw new IndexOutOfBoundsException("Range [" + start + ", " + end + "] out of bounds for length " + editorContent.length());
            }
        } catch (Exception e) {
            api.logging().logToError("Error handling 'Explain me this': " + e.getMessage());
            showError("Error handling 'Explain me this'", e);
        }
    }

    private void handleSelectedScan(MessageEditorHttpRequestResponse editor) {
    try {
        Optional<Range> selectionRange = editor.selectionOffsets();
        if (!selectionRange.isPresent()) {
            return;
        }

        int start = selectionRange.get().startIndexInclusive();
        int end = selectionRange.get().endIndexExclusive();

        // Use editor content instead of reqRes.request()
        String editorContent = editor.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.REQUEST
                ? editor.requestResponse().request().toString()
                : editor.requestResponse().response() != null ? editor.requestResponse().response().toString() : "";

        // Ensure range is within bounds
        if (start >= 0 && end <= editorContent.length()) {
            String selectedContent = editorContent.substring(start, end);
            HttpRequestResponse rr = editor.requestResponse();
            if (rr != null && rr.request() != null) {
                appendDashboardActivity("Manual AI audit queued (selected portion) — " + truncateForIssueTitle(rr.request().url().toString(), 160));
            }
            processAuditRequest(rr, selectedContent, true);
        } else {
            throw new IndexOutOfBoundsException("Range [" + start + ", " + end + "] out of bounds for length " + editorContent.length());
        }
    } catch (Exception e) {
        api.logging().logToError("Error processing selected content: " + e.getMessage());
        showError("Error processing selected content", e);
    }
}


    

    private void handleFullScan(HttpRequestResponse reqRes) {
        if (reqRes == null || reqRes.request() == null) {
            return;
        }
        appendDashboardActivity("Manual AI audit queued (full request/response) — " + truncateForIssueTitle(reqRes.request().url().toString(), 160));
        processAuditRequest(reqRes, null, false);
    }

    private void handleMultipleScan(List<HttpRequestResponse> requests) {
        if (requests == null || requests.isEmpty()) {
            return;
        }
        appendDashboardActivity("Manual AI audit queued — " + requests.size() + " request(s) (multi-select)");

        // Create a thread pool with a fixed size equal to the batch size
        ExecutorService batchExecutor = Executors.newFixedThreadPool(batchSize);
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (HttpRequestResponse reqRes : requests) {
            if (reqRes != null && reqRes.request() != null) {
                futures.add(CompletableFuture.runAsync(() -> {
                    processAuditRequest(reqRes, null, false, null, false);
                }, batchExecutor));
            }
        }

        // Wait for all futures to complete
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        batchExecutor.shutdown();
    }

    private void processAuditRequest(HttpRequestResponse reqRes, String selectedContent, boolean isSelectedPortion) {
        processAuditRequest(reqRes, selectedContent, isSelectedPortion, null, false);
    }

    private void processAuditRequest(HttpRequestResponse reqRes, String selectedContent, boolean isSelectedPortion,
            String trafficContextPreamble, boolean useAutomaticAuditModel) {
        final String preamble = trafficContextPreamble;

        String selectedModel = useAutomaticAuditModel ? getAutomaticAuditModel() : getManualInvestigationModel();
        String[] modelParts = selectedModel.split("/",2);
        String provider;
        String modelNameForApi;

        if (modelParts.length == 2) {
            provider = modelParts[0];
            modelNameForApi = modelParts[1];
        } else {
            // This block should ideally not be reached if all models are formatted as provider/model_name
            log("Warning: processAuditRequest - Model \"" + selectedModel + "\" does not have a provider/model_name format. Attempting to infer.", LogCategory.GENERAL);
            if (selectedModel.startsWith("gpt-")) {
                provider = "openai";
                modelNameForApi = selectedModel;
            } else if (selectedModel.startsWith("claude-")) {
                provider = "claude";
                modelNameForApi = selectedModel;
            } else if (selectedModel.startsWith("gemini-")) {
                provider = "gemini";
                modelNameForApi = selectedModel;
            } else if (selectedModel.startsWith("o1-")) {
                provider = "openrouter";
                modelNameForApi = selectedModel;
            } else if (selectedModel.startsWith("grok")) {
                provider = "xai";
                modelNameForApi = selectedModel;
            } else if (selectedModel.equals("local-llm (LM Studio)")) {
                provider = "local";
                modelNameForApi = selectedModel;
            } else {
                api.logging().raiseErrorEvent("Could nott determine provider for model: " + selectedModel + ", modelParts.length: " + modelParts.length + ", Provider(0): " + modelParts[0] + ", Model Name for API(1): " + modelParts[1]);
                return;
            }
        }
        log("processAuditRequest: Selected Model: " + selectedModel + ", Determined Provider: " + provider + ", Model Name for API: " + modelNameForApi, LogCategory.GENERAL);
        String apiKey = getApiKeyForModel(selectedModel);

        if ("local".equals(provider)) {
            if (localEndpointField.getText().trim().isEmpty()) {
                api.logging().raiseErrorEvent("Local endpoint not configured");
                return;
            }
        } else if (apiKey == null || apiKey.isEmpty()) {
            api.logging().raiseErrorEvent("API key not configured for " + selectedModel);
            return;
        }
    
        ExecutorService auditExecutor = threadPoolManager != null ? threadPoolManager.getExecutor() : null;
        CompletableFuture.runAsync(() -> {
            try {
                String prompt = promptTemplateArea.getText();
                if (prompt == null || prompt.isEmpty()) {
                    prompt = getDefaultPromptTemplate();
                }

                List<String> chunks;
                String contentToChunk;
                String request = "";
                String response = "";

                if (isSelectedPortion && selectedContent != null) {
                    contentToChunk = selectedContent;
                } else if (reqRes != null && reqRes.request() != null) {
                    request = reqRes.request().toString();
                    response = reqRes.response() != null ? reqRes.response().toString() : "";
                    contentToChunk = request + "\n\n" + response;
                    if (preamble != null && !preamble.isEmpty()) {
                        contentToChunk = preamble + "\n\n=== HTTP traffic (request then response) ===\n\n" + contentToChunk;
                    }
                } else if (preamble != null && !preamble.isEmpty()) {
                    contentToChunk = preamble + "\n\n[NOTE: No HTTP traffic was linked to this issue. "
                            + "Analysis is based on issue metadata only — verification steps may be limited.]";
                    api.logging().raiseInfoEvent("AI Auditor: deep-dive running on metadata only (no linked HTTP traffic).");
                } else {
                    api.logging().raiseInfoEvent("Skipping audit for empty request/response content.");
                    return;
                }

                log(String.format("processAuditRequest - Request length: %d, Response length: %d, Combined contentToChunk length: %d",
                    request.length(), response.length(), contentToChunk.length()), LogCategory.GENERAL);

            if (contentToChunk.isEmpty()) {
                api.logging().raiseInfoEvent("Skipping audit for empty request/response content.");
                return;
            }

            chunks = RequestChunker.chunkContent(contentToChunk, prompt);

    
                // Log token and request info
                int promptTokens = RequestChunker.estimateTokens(prompt);
                int contentTokens = RequestChunker.estimateTokens(contentToChunk);
                int totalTokens = promptTokens + contentTokens;
				log(String.format("Estimated PromptTokens=%d, ContentTokens=%d, Total-Tokens=%d, Total-Requests=%d", promptTokens, contentTokens, totalTokens,chunks.size()), LogCategory.TOKEN_INFO);
				
                // Create Set to track processed vulns
                Set<String> processedVulnerabilities = new HashSet<>();
    
                // Use a semaphore to limit concurrency to batchSize
                Semaphore semaphore = new Semaphore(batchSize);
                List<CompletableFuture<Void>> futures = new ArrayList<>();
                for (String chunk : chunks) {
                    try {
                        semaphore.acquire();
                        futures.add(threadPoolManager.submitTask(provider, () -> {
                            try {
                                return sendToAI(selectedModel, apiKey, chunk, true);
                            } finally {
                                semaphore.release();
                            }
                        }).thenAccept(result -> {
                            processAIFindings(result, reqRes, processedVulnerabilities, selectedModel, useAutomaticAuditModel);
                        }));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        showError("Request processing was interrupted", e);
                        break; 
                    }
                }

                // Process all chunkie cheeses and combine results
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .thenRun(() -> {
                        completedTasksCounter.incrementAndGet();
                        log("All chunks processed for the request.", LogCategory.GENERAL);
                    })
                    .exceptionally(e -> {
                        //api.logging().logToError("Error processing AI responses (Model:" + selectedModel + ") " + e.getMessage());
                        showError("Error processing AI responses (Model:" + selectedModel + ")" , e);
                        return null;
                    });
            } catch (Exception e) {
                api.logging().logToError("Error in request processing (Model:" + selectedModel + ")= " + e.getMessage());
                showError("Error processing request (Model:" + selectedModel + ")= " , e);
            }

        }, auditExecutor != null ? auditExecutor : ForkJoinPool.commonPool()).exceptionally(e -> {
            api.logging().logToError("Critical error in request processing: " + e.getMessage());
            showError("Critical error", e);
            return null;
        });

    }
    

    private JSONObject sendToAI(String model, String apiKey, String content) throws Exception {
        return sendToAI(model, apiKey, content, true);
    }

    /**
     * OpenAI-compatible {@code model} string for the local slot. Prefer Connect-tab field; ignore the legacy
     * LM Studio menu label if it is still present in the field or dropdown suffix.
     */
    private String resolveOpenAiCompatibleLocalModelId(String dropdownModelSuffix) throws IllegalArgumentException {
        String legacy = LEGACY_LOCAL_MODEL_PLACEHOLDER;
        String fromField = stripLocalProviderPrefix(getDefaultLocalModelComboText());
        String fromDropdown = stripLocalProviderPrefix(dropdownModelSuffix);
        String resolved = "";
        if (!fromField.isEmpty() && !fromField.equalsIgnoreCase(legacy)) {
            resolved = fromField;
        } else if (!fromDropdown.isEmpty() && !fromDropdown.equalsIgnoreCase(legacy)) {
            resolved = fromDropdown;
        }
        if (resolved.isEmpty()) {
            throw new IllegalArgumentException(
                    "AI Auditor: On Connect → Models, set \"Local LLM model id\" to your server's OpenAI `model` id "
                            + "(Ollama: use a name from `ollama list` on that host). The old label \"" + legacy
                            + "\" is not a valid model id for Ollama.");
        }
        List<String> serverIds = cachedLocalModelIdsFromServer;
        if (serverIds == null || serverIds.isEmpty()) {
            serverIds = fetchLocalOpenAiModelsList();
        }
        if (serverIds != null && !serverIds.isEmpty() && !isLocalModelIdOnServer(resolved, serverIds)) {
            String fallback = serverIds.get(0);
            log("Local model \"" + resolved + "\" is not in GET /v1/models; using \"" + fallback + "\" instead.",
                    LogCategory.GENERAL);
            return fallback;
        }
        return resolved;
    }

    /**
     * @param mergeWithScanPromptTemplate when {@code false}, {@code content} is sent as the full user message (PoC / explain-style tasks).
     */
    private JSONObject sendToAI(String model, String apiKey, String content, boolean mergeWithScanPromptTemplate) throws Exception {
        //String[] modelParts = model.split("/");
		String[] modelParts = model.split("/", 2);

        String provider;
        String modelNameForApi;

        if (modelParts.length == 2 ) {
            provider = modelParts[0];
            modelNameForApi = modelParts[1];
        } else {
            // This block should ideally not be reached if all models are formatted as provider/model_name
            log("Warning: sendToAI - Model \"" + model + "\" does not have a provider/model_name format. Attempting to infer.", LogCategory.GENERAL);
            if (model.startsWith("gpt-")) {
                provider = "openai";
                modelNameForApi = model;
            } else if (model.startsWith("claude-")) {
                provider = "claude";
                modelNameForApi = model;
            } else if (model.startsWith("gemini-")) {
                provider = "gemini";
                modelNameForApi = model;
            } else if (model.startsWith("o1-")) {
                provider = "openrouter";
                modelNameForApi = model;
            } else if (model.startsWith("grok")) {
                provider = "xai";
                modelNameForApi = model;
            } else if (model.equals("local-llm (LM Studio)")) {
                provider = "local";
                modelNameForApi = model;
            } else {
                throw new IllegalArgumentException("Unsupported model: " + model);
            }
        }
        log("sendToAI: Selected Model: " + model + ", Determined Provider: " + provider + ", Model Name for API: " + modelNameForApi, LogCategory.GENERAL);

        URL url = null; // Initialize url to null
        JSONObject jsonBody = new JSONObject();
        String finalPrompt = "";

        if (!mergeWithScanPromptTemplate) {
            finalPrompt = content;
        } else if (content.toLowerCase().contains("content to analyze") || content.toLowerCase().contains("content to explain")) {
			finalPrompt = content;
		} else {
			String prompt = promptTemplateArea.getText();

			if (prompt == null || prompt.isEmpty()) {
				prompt = getDefaultPromptTemplate();
			}

			// Automate Prompt Augmentation for Reporting (Task 6)
			if (!prompt.toLowerCase().contains("format") &&
				!prompt.toLowerCase().contains("json") &&
				!prompt.toLowerCase().contains("structure") &&
				!prompt.toLowerCase().contains("vulnerability") &&
				!prompt.toLowerCase().contains("content to explain") &&
				!prompt.toLowerCase().contains("severity"))
			{
				prompt += "\n\nIMPORTANT:\nOnly return JSON with findings, no other content!\n\nFormat findings as JSON with the following structure:\n" +
						  "{\n" +
						  "  \"findings\": [{\n" +
						  "    \"vulnerability\": \"Clear, specific, concise title of issue\",\n" +
						  "    \"location\": \"Exact location in request/response (parameter, header, or path)\",\n" +
						  "    \"explanation\": \"Detailed technical explanation with evidence from the request/response\",\n" +
						  "    \"exploitation\": \"Specific steps to reproduce/exploit\",\n" +
						  "    \"validation_steps\": \"Steps to validate the finding\",\n" +
						  "    \"severity\": \"HIGH|MEDIUM|LOW|INFORMATION\",\n" +
						  "    \"confidence\": \"CERTAIN|FIRM|TENTATIVE\"\n" +
						  "  }]\n" +
						  "}\n";
			}
			finalPrompt = prompt + "\n\nContent to analyze:\n" + content;
		}
		
        // Configure endpoint and payload
        // log("DEBUG - - - provider=" + provider);
		switch (provider) {
            case "openai":
                url = new URL("https://api.openai.com/v1/chat/completions");
                jsonBody.put("model", modelNameForApi)
                        .put("messages", new JSONArray()
                                .put(new JSONObject()
                                        .put("role", "user")
                                        .put("content", finalPrompt)));
                break;
            case "openrouter":
                url = new URL("https://openrouter.ai/api/v1/chat/completions");
                jsonBody.put("model", modelNameForApi)
                        .put("messages", new JSONArray()
                                .put(new JSONObject()
                                        .put("role", "user")
                                        .put("content", finalPrompt)));
                break;

            case "xai":
                url = new URL("https://api.x.ai/v1/chat/completions");
                jsonBody.put("model", modelNameForApi)
                        .put("messages", new JSONArray()
                                .put(new JSONObject()
                                        .put("role", "user")
                                        .put("content", finalPrompt)));
                break;

            case "gemini":
                // URL will be constructed inside the retry loop with the current API key
                jsonBody.put("contents", new JSONArray()
                        .put(new JSONObject()
                                .put("parts", new JSONArray()
                                        .put(new JSONObject()
                                                .put("text", finalPrompt)))));
                break;

            case "claude":
                url = new URL("https://api.anthropic.com/v1/messages");
                jsonBody.put("model", modelNameForApi)
                        .put("max_tokens", CLAUDE_MAX_OUTPUT_TOKENS)
                        .put("messages", new JSONArray()
                                .put(new JSONObject()
                                        .put("role", "user")
                                        .put("content", finalPrompt)));
                break;

            case "local":
				url = new URL(normalizeLocalLlmBaseUrl() + "/chat/completions");
                String localModelForApi = resolveOpenAiCompatibleLocalModelId(modelNameForApi);
			    jsonBody.put("model", localModelForApi)
			            .put("temperature", 0.7)
                        .put("stream", false)
                        .put("messages", new JSONArray()
                                .put(new JSONObject()
                                        .put("role", "user")
                                        .put("content", finalPrompt)));
                log("Local LLM chat URL=" + url + " model=" + localModelForApi, LogCategory.GENERAL);
                break;

            default:
                throw new IllegalArgumentException("Unsupported provider: " + provider);
        }

        // Retry logic
        Exception lastException = null;
        String currentApiKey = apiKey; // Use the initial API key

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            try {
                if ("gemini".equals(provider)) {
                    // For Gemini, get the current key and pass it to sendRequest
                    currentApiKey = getNextGeminiApiKey(false); // Don't cycle yet, just get current
                    if (currentApiKey == null || currentApiKey.isEmpty()) {
                        throw new Exception("No Gemini API keys configured.");
                    }
                    url = new URL("https://generativelanguage.googleapis.com/v1beta/models/" + modelNameForApi + ":generateContent?key=" + currentApiKey);
                    log("Using Gemini API Key: ..." + currentApiKey.substring(currentApiKey.length() - 4), LogCategory.GENERAL);
                }
                return sendRequest(url, jsonBody, currentApiKey, model);
            } catch (Exception e) {
                lastException = e;
                api.logging().logToError("Attempt " + (attempt + 1) + " failed: " + e.getMessage());
                log("sendToAI: Attempt " + (attempt + 1) + " failed for model " + model + ": " + e.getMessage(), LogCategory.GENERAL);

                // If Gemini and it's a quota/rate limit error, try next key
                if ("gemini".equals(provider) && (e.getMessage().contains("429") || e.getMessage().contains("quota") || e.getMessage().contains("rate limit") || e.getMessage().contains("API key not valid"))) {
                    String failedKey = currentApiKey;
                    currentApiKey = getNextGeminiApiKey(true); // Cycle to the next key
                    if (currentApiKey == null || currentApiKey.isEmpty()) {
                        api.logging().logToError("All Gemini API keys exhausted or no keys configured.");
                        throw new Exception("All Gemini API keys exhausted or no keys configured.", lastException);
                    }
                    log("Gemini API Key ..." + failedKey.substring(failedKey.length() - 4) + " exceeded quota (or API error). Switching to key: ..." + currentApiKey.substring(currentApiKey.length() - 4), LogCategory.GENERAL);
                }

                Thread.sleep(retryDelayMs * (attempt + 1));
            }
        }
        throw new Exception("Failed after " + maxRetries + " attempts", lastException);
		
    }
    
    
    

    /**
     * Extension outbound proxy (AI Auditor settings) should not swallow localhost / LM Studio — those stay direct even
     * when Burp’s own upstream proxy is configured separately.
     */
    private boolean shouldBypassExtensionProxyForUrl(URL url) {
        if (url == null) {
            return true;
        }
        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return true;
        }
        String h = host.toLowerCase(Locale.ROOT);
        if ("localhost".equals(h) || "127.0.0.1".equals(h) || "::1".equals(h) || "0:0:0:0:0:0:0:1".equals(h)) {
            return true;
        }
        if (localEndpointField != null) {
            try {
                String ep = localEndpointField.getText().trim();
                if (!ep.isEmpty()) {
                    URL lu = new URL(ep);
                    if (h.equalsIgnoreCase(lu.getHost())) {
                        return true;
                    }
                }
            } catch (Exception ignored) {
            }
        }
        return false;
    }

    /**
     * Same proxy rules as {@link #sendRequest}: extension HTTP proxy applies except for localhost / local LM host.
     */
    private HttpURLConnection openValidationConnection(URL url) throws IOException {
        HttpURLConnection conn;
        String proxyString = proxyField != null ? proxyField.getText().trim() : "";
        if (!proxyString.isEmpty() && !shouldBypassExtensionProxyForUrl(url)) {
            try {
                String[] proxyParts = proxyString.split(":");
                if (proxyParts.length != 2) {
                    conn = (HttpURLConnection) url.openConnection();
                } else {
                    String pHost = proxyParts[0].trim();
                    int pPort = Integer.parseInt(proxyParts[1].trim());
                    Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(pHost, pPort));
                    conn = (HttpURLConnection) url.openConnection(proxy);
                }
            } catch (Exception e) {
                api.logging().logToError("Validation: invalid extension proxy, using direct connection: " + e.getMessage());
                conn = (HttpURLConnection) url.openConnection();
            }
        } else {
            conn = (HttpURLConnection) url.openConnection();
        }
        conn.setConnectTimeout(VALIDATION_CONNECT_MS);
        conn.setReadTimeout(VALIDATION_READ_MS);
        return conn;
    }

    private JSONObject sendRequest(URL url, JSONObject jsonBody, String apiKey, String model) throws Exception {
    HttpURLConnection conn = null;
    BufferedReader reader = null;
    try {
        String proxyString = proxyField.getText().trim();
        String[] modelParts = model.split("/",2);
        String provider;

        if (modelParts.length == 2) {
            provider = modelParts[0];
        } else {
            provider = MODEL_MAPPING.get(model);
        }

        if (!proxyString.isEmpty() && !shouldBypassExtensionProxyForUrl(url)) {
            try {
                String[] proxyParts = proxyString.split(":");
                if (proxyParts.length != 2) {
                    throw new Exception("Invalid proxy format. Use IP:Port.");
                }
                String host = proxyParts[0];
                int port = Integer.parseInt(proxyParts[1]);
                Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(host, port));
                conn = (HttpURLConnection) url.openConnection(proxy);
            } catch (Exception e) {
                showError("Invalid proxy setting: " + proxyString, e);
                // Fallback to no proxy
                conn = (HttpURLConnection) url.openConnection();
            }
        } else {
            conn = (HttpURLConnection) url.openConnection();
        }
        log("Final URL for connection: " + url.toString(), LogCategory.GENERAL);

        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setConnectTimeout(AI_CONNECT_TIMEOUT_MS);
        conn.setReadTimeout("local".equals(provider) ? AI_READ_TIMEOUT_LOCAL_MS : AI_READ_TIMEOUT_CLOUD_MS);

        switch (provider) {
            case "claude":
                conn.setRequestProperty("x-api-key", apiKey);
                conn.setRequestProperty("anthropic-version", "2023-06-01");
                break;
            case "openai":
            case "openrouter":
            case "xai":
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
                break;
            case "gemini":
                // API key is already included in the URL
                break;
            case "local":

				if (apiKey != null && !apiKey.isEmpty()) {
                    conn.setRequestProperty("Authorization", "Bearer " + apiKey);
                }
                break;
        }

		log(" -Sending " + conn.getRequestMethod() + " to " + url, LogCategory.GENERAL);
        
		// Send the request body
        if (jsonBody != null) {
            conn.setDoOutput(true);

			log("  --Body: " + jsonBody.toString(), LogCategory.REQUEST_BODY);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.toString().getBytes(StandardCharsets.UTF_8));
                os.flush();
            }
        }

        // Read the response
        int responseCode = conn.getResponseCode();
        InputStream inputStream = (responseCode == 200) ? conn.getInputStream() : conn.getErrorStream();
        reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        StringBuilder responseBuilder = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            responseBuilder.append(line);
        }

        String responseContent = responseBuilder.toString();

        // Log the response for debugging
        log("API Response: " + responseContent, LogCategory.API_RESPONSE);

        if (responseCode == 200) {
            return new JSONObject(responseContent);
        } else {
            throw new Exception("API error " + responseCode + ": " + responseContent);
        }


    }catch (Exception e) {
        // ---------- unified error handling ----------
        String prefix = "Error  - Model: " + model + " - ";
        api.logging().logToError(prefix + e.getMessage());
        logDebug(prefix, e);                     // keeps stack-trace
        throw e;                                  // re-throw so callers can still handle it
    } finally {
        SafeUtils.closeQuietly(reader);
        SafeUtils.disconnectQuietly(conn);
    }
}

private void processAIFindings(JSONObject aiResponse, HttpRequestResponse requestResponse, Set<String> processedVulnerabilities, String model, boolean verifyWithPremiumModel) {
    try {
        appendDashboardActivity("AI analysis started — " + model);
        log("AI Response: " + aiResponse.toString(2), LogCategory.AI_RESPONSE_FULL);

        // Determine the actual model used from the response JSON
		String actualModel = aiResponse.optString("model");
		String finalModelName;

		if (actualModel != null && !actualModel.isEmpty() && !actualModel.equals(model)) {
			finalModelName = model + " (" + actualModel + ")"; // e.g., "gpt-4o (gpt-4o-2024-05-13)"
		} else {
			finalModelName = model;
		}



        // Extract content based on the provider (using the original requested model to know the provider)
        String content = extractContentFromResponse(aiResponse, model);
        if (content == null || content.isEmpty()) {
            throw new JSONException("No valid content found in AI response.");
        }

        // Log raw content
        log("Raw content: " + content, LogCategory.RAW_CONTENT);

        String findingsJsonText = extractFindingsJsonText(content);
        if (findingsJsonText == null) {
            appendDashboardActivity("AI analysis skipped — model returned non-JSON findings format");
            log("AI findings skipped: response did not contain parseable JSON object with 'findings'.", LogCategory.GENERAL);
            return;
        }

        log("Extracted JSON: " + findingsJsonText, LogCategory.EXTRACTED_JSON);

        // Parse findings JSON
        JSONObject findingsJson = new JSONObject(findingsJsonText);

        // Ensure findings key exists
        if (!findingsJson.has("findings")) {
            throw new JSONException("Key 'findings' not found in extracted JSON.");
        }

        // Parse findings array
        JSONArray findings = findingsJson.getJSONArray("findings");
        int addedCount = 0;
        int skippedWeakCount = 0;
        int skippedUnverifiedCount = 0;
        int skippedVerifyErrorCount = 0;
        int premiumChecks = 0;

        PremiumVerificationContext premiumContext = null;
        if (verifyWithPremiumModel) {
            premiumContext = resolvePremiumVerificationContext(model);
        }
        final String verificationEvidence = buildRequestResponseEvidenceBlock(requestResponse);

        for (int i = 0; i < findings.length(); i++) {
            JSONObject finding = findings.getJSONObject(i);

			// --- SAFETY GUARD -------------------------------------------------
			if (requestResponse == null
					|| requestResponse.request() == null
					|| requestResponse.httpService() == null) {
				log("Skipping finding '" + finding.optString("vulnerability", "unknown")
					+ "' because request/response is missing.", LogCategory.GENERAL);
				continue;                 // <-- do NOT attempt to build an issue
			}
			// ------------------------------------------------------------------
			
			
            // Skip duplicate vulns

			if (requestResponse == null) {
			    log("Skipping finding because requestResponse is null.",
			        LogCategory.GENERAL);
			    continue;
			}
			
            String hash = generateVulnerabilityHash(finding, requestResponse);
            if (processedVulnerabilities.contains(hash)) {
                continue;
            }
            processedVulnerabilities.add(hash);

            // Parse severity and confidence
            AuditIssueSeverity severity = parseSeverity(finding.optString("severity", "INFORMATION"));
            AuditIssueConfidence confidence = parseConfidence(finding.optString("confidence", "TENTATIVE"));

            if (!passesFindingQualityGate(finding, severity, confidence)) {
                skippedWeakCount++;
                continue;
            }

            String premiumVerificationNote = "";
            if (verifyWithPremiumModel && premiumContext != null && premiumChecks < MAX_PREMIUM_VERIFY_PER_RESPONSE) {
                premiumChecks++;
                PremiumVerificationResult vr = verifyFindingWithPremiumModel(finding, verificationEvidence, premiumContext, severity, confidence);
                if (vr == null) {
                    skippedVerifyErrorCount++;
                    continue;
                }
                if (!vr.verified) {
                    skippedUnverifiedCount++;
                    continue;
                }
                severity = vr.severity;
                confidence = vr.confidence;
                premiumVerificationNote = vr.reason;
            }

			// Build AIAuditIssue
			if (requestResponse == null) {
				log("Skipping finding '" + finding.optString("vulnerability", "Unknown")
					+ "' because requestResponse is null.", LogCategory.GENERAL);
				continue;
			}

            // Build issue details
            StringBuilder issueDetail = new StringBuilder();
            issueDetail.append("__Issue identified by AI Auditor__\n\n");
            issueDetail.append("**Location:** ").append(finding.optString("location", "Unknown")).append("\n\n");
            issueDetail.append("**Detailed Explanation:**\n").append(finding.optString("explanation", "No explanation provided")).append("\n\n");
            if (!premiumVerificationNote.isEmpty()) {
                issueDetail.append("**Premium Verification Note:** ").append(premiumVerificationNote).append("\n\n");
            }
            issueDetail.append("**Confidence Level:** ").append(confidence.name()).append("\n");
            issueDetail.append("**Severity Level:** ").append(severity.name());


            // Build AIAuditIssue
			AIAuditIssue issue = new AIAuditIssue.Builder()
					.name("AI Audit: " + finding.optString("vulnerability", "Unknown Vulnerability"))
					.detail(issueDetail.toString())
					.endpoint(requestResponse.request().url().toString())
					.severity(severity)
					.confidence(confidence)
					.requestResponses(Collections.singletonList(requestResponse))
					.modelUsed(finalModelName != null ? finalModelName : "unknown model")
					.build();

			// Debug: Log constructed AIAuditIssue for troubleshooting
			//log("Constructed AIAuditIssue: " + issue.toString(), LogCategory.GENERAL);
            
			// Add issue to sitemap
            api.siteMap().add(issue);
            addedCount++;
        }

        List<String> stats = new ArrayList<>();
        if (skippedWeakCount > 0) {
            stats.add(skippedWeakCount + " weak filtered");
        }
        if (skippedUnverifiedCount > 0) {
            stats.add(skippedUnverifiedCount + " rejected by premium verification");
        }
        if (skippedVerifyErrorCount > 0) {
            stats.add(skippedVerifyErrorCount + " premium verification error");
        }
        if (verifyWithPremiumModel && premiumContext == null) {
            stats.add("premium verification unavailable");
        }
        if (verifyWithPremiumModel && premiumChecks >= MAX_PREMIUM_VERIFY_PER_RESPONSE) {
            stats.add("premium verification cap reached (" + MAX_PREMIUM_VERIFY_PER_RESPONSE + ")");
        }

        if (addedCount > 0) {
            String suffix = stats.isEmpty() ? "" : ", " + String.join(", ", stats);
            appendDashboardActivity("AI analysis complete — " + addedCount + " finding(s) added" + suffix);
        } else {
            if (stats.isEmpty()) {
                appendDashboardActivity("AI analysis complete — no findings");
            } else {
                appendDashboardActivity("AI analysis complete — no actionable findings (" + String.join(", ", stats) + ")");
            }
        }
    } catch (Exception e) {
        appendDashboardActivity("AI analysis failed — " + formatExceptionChainForDashboard(e));
        api.logging().logToError("Error processing AI findings: " + e.getMessage());
    }
}

/**
 * Best-effort parser for model output expected to contain a JSON object with a "findings" array.
 * Returns null when no parseable findings JSON is present.
 */
private String extractFindingsJsonText(String content) {
    if (content == null) {
        return null;
    }
    String text = content.trim();
    if (text.isEmpty()) {
        return null;
    }

    // Try fenced code blocks first: ```json ... ``` (or ``` ... ```)
    Pattern fencePattern = Pattern.compile("```(?:json)?\\s*\\n(.*?)\\n```", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    Matcher fenceMatcher = fencePattern.matcher(text);
    while (fenceMatcher.find()) {
        String candidate = fenceMatcher.group(1).trim();
        if (hasFindingsKey(candidate)) {
            return candidate;
        }
    }

    // If whole response is already JSON, use it
    if (hasFindingsKey(text)) {
        return text;
    }

    // Fallback: trim to outermost braces and retry
    int start = text.indexOf('{');
    int end = text.lastIndexOf('}');
    if (start >= 0 && end > start) {
        String candidate = text.substring(start, end + 1).trim();
        if (hasFindingsKey(candidate)) {
            return candidate;
        }
    }
    return null;
}

private boolean hasFindingsKey(String candidate) {
    try {
        JSONObject obj = new JSONObject(candidate);
        return obj.has("findings") && obj.optJSONArray("findings") != null;
    } catch (Exception ignored) {
        return false;
    }
}

/**
 * Conservative gate to reduce false positives in automatic scan issue creation.
 * Keeps only findings with stronger confidence, impact, and concrete technical evidence.
 */
private boolean passesFindingQualityGate(JSONObject finding, AuditIssueSeverity severity, AuditIssueConfidence confidence) {
    if (finding == null) {
        return false;
    }
    if (severity == AuditIssueSeverity.INFORMATION) {
        return false;
    }
    if (confidence == AuditIssueConfidence.TENTATIVE) {
        return false;
    }
    if (severity == AuditIssueSeverity.LOW && confidence != AuditIssueConfidence.CERTAIN) {
        return false;
    }

    String title = finding.optString("vulnerability", "");
    String location = finding.optString("location", "");
    String explanation = finding.optString("explanation", "");
    String exploitation = finding.optString("exploitation", "");
    String validation = finding.optString("validation_steps", "");

    if (isLikelyPlaceholder(location) || isLikelyPlaceholder(explanation) || isLikelyPlaceholder(title)) {
        return false;
    }
    if (explanation.length() < 80) {
        return false;
    }

    String evidenceText = location + "\n" + exploitation + "\n" + validation;
    return hasConcreteTechnicalSignal(evidenceText);
}

private boolean isLikelyPlaceholder(String text) {
    if (text == null) {
        return true;
    }
    String t = text.trim().toLowerCase(Locale.ROOT);
    return t.isEmpty()
            || "unknown".equals(t)
            || "n/a".equals(t)
            || "none".equals(t)
            || t.contains("no explanation provided");
}

private boolean hasConcreteTechnicalSignal(String text) {
    if (text == null || text.trim().isEmpty()) {
        return false;
    }
    String t = text.toLowerCase(Locale.ROOT);
    return t.contains("http/1.1")
            || t.contains("http/2")
            || t.matches("(?s).*\\b(get|post|put|patch|delete|head|options)\\b.*")
            || t.matches("(?s).*\\bstatus\\s*[:=]?\\s*\\d{3}\\b.*")
            || t.matches("(?s).*\\b[a-z0-9_\\-]+\\s*=\\s*[^\\s]+.*")
            || t.contains("/")
            || t.contains("authorization")
            || t.contains("cookie")
            || t.contains("csrf")
            || t.contains("samesite")
            || t.contains("secure");
}

private PremiumVerificationContext resolvePremiumVerificationContext(String sourceModel) {
    String premiumModel = getManualInvestigationModel();
    if (premiumModel == null || premiumModel.trim().isEmpty() || "Default".equals(premiumModel)) {
        return null;
    }
    String[] modelParts = premiumModel.split("/", 2);
    String provider = modelParts.length == 2 ? modelParts[0] : "";
    String apiKey = getApiKeyForModel(premiumModel);
    if ("local".equals(provider)) {
        if (localEndpointField == null || localEndpointField.getText().trim().isEmpty()) {
            return null;
        }
    } else if (apiKey == null || apiKey.trim().isEmpty()) {
        return null;
    }
    return new PremiumVerificationContext(premiumModel, apiKey);
}

private String buildRequestResponseEvidenceBlock(HttpRequestResponse requestResponse) {
    if (requestResponse == null || requestResponse.request() == null) {
        return "";
    }
    String request = requestResponse.request().toString();
    String response = requestResponse.response() != null ? requestResponse.response().toString() : "(no response captured)";
    return "=== HTTP request ===\n" + request + "\n\n=== HTTP response ===\n" + response;
}

private PremiumVerificationResult verifyFindingWithPremiumModel(
        JSONObject finding,
        String evidenceBlock,
        PremiumVerificationContext context,
        AuditIssueSeverity fallbackSeverity,
        AuditIssueConfidence fallbackConfidence) {
    if (context == null || finding == null) {
        return null;
    }
    try {
        String verificationPrompt = """
                You are a strict application-security verifier reviewing a candidate finding generated by another model.
                Confirm ONLY when the provided HTTP evidence supports a real issue. If uncertain, reject.

                Return strict JSON only:
                {
                  "verified": true|false,
                  "reason": "Short technical reason grounded in evidence",
                  "severity": "HIGH|MEDIUM|LOW|INFORMATION",
                  "confidence": "CERTAIN|FIRM|TENTATIVE"
                }
                """.stripIndent()
                + "\n\nCandidate finding JSON:\n" + finding.toString()
                + "\n\nEvidence:\n" + evidenceBlock;

        JSONObject verificationResponse = sendToAI(context.model, context.apiKey, verificationPrompt, false);
        String verificationText = extractContentFromResponse(verificationResponse, context.model);
        String verificationJsonText = extractFirstJsonObjectText(verificationText);
        if (verificationJsonText == null) {
            return null;
        }
        JSONObject verification = new JSONObject(verificationJsonText);
        boolean verified = verification.optBoolean("verified", false);
        AuditIssueSeverity severity = parseSeverity(verification.optString("severity", fallbackSeverity.name()));
        AuditIssueConfidence confidence = parseConfidence(verification.optString("confidence", fallbackConfidence.name()));
        String reason = verification.optString("reason", "");
        return new PremiumVerificationResult(verified, severity, confidence, reason);
    } catch (Exception e) {
        log("Premium verification error: " + e.getMessage(), LogCategory.GENERAL);
        return null;
    }
}

private String extractFirstJsonObjectText(String text) {
    if (text == null) {
        return null;
    }
    String trimmed = text.trim();
    if (trimmed.isEmpty()) {
        return null;
    }
    // Try direct JSON first
    try {
        new JSONObject(trimmed);
        return trimmed;
    } catch (Exception ignored) {
    }

    Pattern fencePattern = Pattern.compile("```(?:json)?\\s*\\n(.*?)\\n```", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    Matcher fenceMatcher = fencePattern.matcher(trimmed);
    while (fenceMatcher.find()) {
        String candidate = fenceMatcher.group(1).trim();
        try {
            new JSONObject(candidate);
            return candidate;
        } catch (Exception ignored) {
        }
    }

    int start = trimmed.indexOf('{');
    int end = trimmed.lastIndexOf('}');
    if (start >= 0 && end > start) {
        String candidate = trimmed.substring(start, end + 1).trim();
        try {
            new JSONObject(candidate);
            return candidate;
        } catch (Exception ignored) {
        }
    }
    return null;
}


private String extractContentFromResponse(JSONObject response, String model) {
    return extractContentFromResponse(response, model, true);
}

private String extractContentFromResponse(JSONObject response, String model, boolean stripNewlines) {
    try {
        String[] modelParts = model.split("/",2);
        String provider;

        if (modelParts.length == 2) {
            provider = modelParts[0];
        } else {
            // This block should ideally not be reached if all models are formatted as provider/model_name
            log("Warning: extractContentFromResponse - Model \"" + model + "\" does not have a provider/model_name format. Attempting to infer.", LogCategory.GENERAL);
            if (model.startsWith("gpt-")) {
                provider = "openai";
            } else if (model.startsWith("claude-")) {
                provider = "claude";
            } else if (model.startsWith("gemini-")) {
                provider = "gemini";
            } else if (model.startsWith("o1-")) {
                provider = "openrouter";
            } else if (model.startsWith("grok")) {
                provider = "xai";
            } else if (model.equals("local-llm (LM Studio)")) {
                provider = "local";
            } else {
                throw new IllegalArgumentException("Unknown model: " + model);
            }
        }
        log("extractContentFromResponse: Selected Model: " + model + ", Determined Provider: " + provider, LogCategory.GENERAL);


        // Log raw response for debugging
        log("Raw response: " + response.toString(), LogCategory.API_RESPONSE);

        switch (provider) {
            case "claude":
                // Extract "text" for Claude
                if (response.has("content")) {
                    JSONArray contentArray = response.getJSONArray("content");
                    if (contentArray.length() > 0) {
                        return contentArray.getJSONObject(0).getString("text");
                    }
                }
                break;

            case "gemini":
                // Extract "text" under "candidates" > "content" > "parts" for Gemini
                JSONArray candidates = response.optJSONArray("candidates");
                if (candidates != null && candidates.length() > 0) {
                    JSONObject candidate = candidates.getJSONObject(0);
                    JSONObject content = candidate.optJSONObject("content");
                    if (content != null) {
                        JSONArray parts = content.optJSONArray("parts");
                        if (parts != null && parts.length() > 0) {
                            return parts.getJSONObject(0).getString("text");
                        }
                    }
                }
                break;

            case "openai":
            case "openrouter":
            case "xai":
                return response
                        .getJSONArray("choices")
                        .getJSONObject(0)
                        .getJSONObject("message")
                        .getString("content");

            case "local":
                // return response.optString("content");
				// Extract "content" under "choices" > "message" for LM Studio (OpenAI format)
				JSONArray choices = response.optJSONArray("choices");
				if (choices != null && choices.length() > 0) {
					JSONObject choice = choices.getJSONObject(0);
					JSONObject message = choice.optJSONObject("message");
					if (message != null) {
						// return message.optString("content");
						return cleanLLMResponse(message.optString("content"), stripNewlines);
					}
				}
				break;
            default:
                throw new IllegalArgumentException("Unsupported provider: " + provider);
        }
    } catch (Exception e) {
        api.logging().logToError("Error extracting content from response: " + e.getMessage());
    }
    return "";
}

public static String cleanLLMResponse(String rawResponse, boolean removeNewlines) {
    if (rawResponse == null) return null;

    // Remove <think>...</think> including the tags to with with thinking models (case-insensitive)
    String cleaned = rawResponse.replaceAll("(?is)<think>.*?</think>", "");

    // Remove newlines
    if (removeNewlines) {
        cleaned = cleaned.replaceAll("\\r?\\n", " ").trim();
    }

    return cleaned.trim();
}


private String formatFindingDetails(JSONObject finding) {
    if (finding == null) return "";

    StringBuilder details = new StringBuilder();
    details.append("<div style='font-family: Arial, sans-serif;'>");
    
    String location = SafeUtils.safeGetString(finding, "location");
    if (!location.isEmpty()) {
        details.append("<b>Location:</b><br/>")
               .append(escapeHtml(location))
               .append("<br/><br/>");
    }
    
    String explanation = SafeUtils.safeGetString(finding, "explanation");
    if (!explanation.isEmpty()) {
        details.append("<b>Technical Details:</b><br/>")
               .append(escapeHtml(explanation))
               .append("<br/><br/>");
    }

    String exploitation = SafeUtils.safeGetString(finding, "exploitation");
    if (!exploitation.isEmpty()) {
        details.append("<b>Exploitation Method:</b><br/>")
               .append(escapeHtml(exploitation))
               .append("<br/><br/>");
    }

    String validation = SafeUtils.safeGetString(finding, "validation_steps");
    if (!validation.isEmpty()) {
        details.append("<b>Validation Steps:</b><br/>")
               .append(escapeHtml(validation))
               .append("<br/><br/>");
    }

    details.append("<b>Confidence Level:</b> ")
           .append(SafeUtils.safeGetString(finding, "confidence"))
           .append("<br/>")
           .append("<b>Severity Level:</b> ")
           .append(SafeUtils.safeGetString(finding, "severity"));

    details.append("</div>");
    return details.toString();
}

private String escapeHtml(String text) {
    if (text == null) return "";
    return text.replace("&", "&amp;")
              .replace("<", "&lt;")
              .replace(">", "&gt;")
              .replace("\"", "&quot;")
              .replace("'", "&#39;")
              .replace("\n", "<br/>");
}

private String generateVulnerabilityHash(JSONObject finding, HttpRequestResponse reqRes) {
    // Collect the three pieces we want to hash
    String vulnerability = SafeUtils.safeGetString(finding, "vulnerability");
    String location      = SafeUtils.safeGetString(finding, "location");
    String url           = (reqRes != null && reqRes.request() != null)
                           ? reqRes.request().url()
                           : null;

    // Turn any null into an empty string so nothing ever throws
    vulnerability = vulnerability == null ? "" : vulnerability;
    location      = location      == null ? "" : location;
    url           = url           == null ? "" : url;

    /*
     * Objects.hash(Object…) never dereferences its arguments,
     * so even if every field is missing we still get a perfectly
     * valid, repeatable integer that we return as a String.
     */
    int safeHash = Objects.hash(vulnerability, location, url);
    return Integer.toString(safeHash);
}

private AuditIssueSeverity parseSeverity(String severity) {
    switch (severity.toUpperCase()) {
        case "HIGH": return AuditIssueSeverity.HIGH;
        case "MEDIUM": return AuditIssueSeverity.MEDIUM;
        case "LOW": return AuditIssueSeverity.LOW;
        default: return AuditIssueSeverity.INFORMATION;
    }
}

private AuditIssueConfidence parseConfidence(String confidence) {
    switch (confidence.toUpperCase()) {
        case "CERTAIN": return AuditIssueConfidence.CERTAIN;
        case "FIRM": return AuditIssueConfidence.FIRM;
        default: return AuditIssueConfidence.TENTATIVE;
    }
}

private String resolveModelFromDropdown(JComboBox<String> dropdown) {
    if (dropdown == null) {
        return "Default";
    }
    String model = (String) dropdown.getSelectedItem();
    if (!"Default".equals(model)) {
        return model;
    }
    if (!new String(openaiKeyField.getPassword()).isEmpty()) {
        return cachedDefaultOpenai;
    }
    if (!geminiApiKeys.isEmpty()) {
        return cachedDefaultGemini;
    }
    if (!new String(claudeKeyField.getPassword()).isEmpty()) {
        return cachedDefaultClaude;
    }
    if (!new String(openrouterKeyField.getPassword()).isEmpty()) {
        return cachedDefaultOpenrouter;
    }
    if (!new String(xaiKeyField.getPassword()).isEmpty()) {
        return cachedDefaultXai;
    }
    if (!localEndpointField.getText().trim().isEmpty()) {
        return cachedDefaultLocal;
    }
    return "Default";
}

private String getAutomaticAuditModel() {
    return resolveModelFromDropdown(automaticAuditModelDropdown);
}

private String getManualInvestigationModel() {
    return resolveModelFromDropdown(manualInvestigationModelDropdown);
}

private String getApiKeyForModel(String model) {
    String[] modelParts = model.split("/",2);
    String provider;

    //log("DEBUG - S2-getApiKeyForModel Selected Model: " + model + ", modelParts.length: " + modelParts.length + ", Determined Provider: " + modelParts[0] + ", Model Name for API: " + modelParts[1]);

    if (modelParts.length == 2) {
        provider = modelParts[0];
    } else {
        // This else block should ideally not be reached if all models are formatted as provider/model_name
        // Log a warning if it is, indicating a model format issue
        log("Warning: Model \"" + model + "\" does not have a provider/model_name format. Attempting to infer.", LogCategory.GENERAL);
        // Fallback for models that might not be formatted correctly (e.g., from old saved settings)
        if (model.startsWith("gpt-")) {
            provider = "openai";
        } else if (model.startsWith("claude-")) {
            provider = "claude";
        } else if (model.startsWith("gemini-")) {
            provider = "gemini";
        } else if (model.startsWith("o1-")) { // OpenRouter specific models without explicit prefix
            provider = "openrouter";
        } else if (model.startsWith("grok")) {
            provider = "xai";
        } else if (model.equals("local-llm (LM Studio)")) {
            provider = "local";
        } else {
            log("Error: Could noot determine provider for model: " + model, LogCategory.GENERAL);
            return null; // Unknown provider
        }
    }
    log("getApiKeyForModel: Determined provider: " + provider + " for model: " + model, LogCategory.GENERAL);
    switch (provider) {
        case "openai": return new String(openaiKeyField.getPassword());
        case "openrouter": return new String(openrouterKeyField.getPassword());
        case "xai": return new String(xaiKeyField.getPassword());
        case "gemini":
            String[] keys = geminiKeyField.getText().split("\\n");
            if (keys.length > 0) {
                return keys[0].trim();
            }
            return null;
        case "claude": return new String(claudeKeyField.getPassword());
        case "local": return new String(localKeyField.getPassword());
        default: return null;
    }
}

private String getNextGeminiApiKey(boolean cycle) {
    if (geminiApiKeys.isEmpty()) {
        return null;
    }
    if (cycle) {
        currentGeminiKeyIndex.incrementAndGet();
    }
    int index = currentGeminiKeyIndex.get() % geminiApiKeys.size();
    return geminiApiKeys.get(index).trim();
}

    /**
     * Normalizes a default model line to {@code provider/modelId}. OpenRouter accepts {@code org/model} without the
     * {@code openrouter/} prefix in the UI field.
     */
    private static String normalizeDefaultModelLine(String provider, String text, String fallbackFull) {
        if (text == null) {
            return fallbackFull;
        }
        String t = text.trim();
        if (t.isEmpty()) {
            return fallbackFull;
        }
        if (t.startsWith(provider + "/")) {
            return t;
        }
        if (!t.contains("/")) {
            return provider + "/" + t;
        }
        if ("openrouter".equals(provider)) {
            return "openrouter/" + t;
        }
        return t;
    }

    /**
     * {@code default_model_local} historically stored {@code local/local-llm (LM Studio)}; normalize to a real id and
     * show only the model suffix in the text field (Connect tab).
     */
    private static String migrateLoadedLocalDefaultModelPreference(String persisted) {
        if (persisted == null) {
            return "";
        }
        String t = persisted.trim();
        if (t.isEmpty()) {
            return "";
        }
        if ("local/local-llm (LM Studio)".equalsIgnoreCase(t)
                || LEGACY_LOCAL_MODEL_PLACEHOLDER.equalsIgnoreCase(t)) {
            return "gemma4:e4b";
        }
        final String localPrefix = "local/";
        if (t.regionMatches(true, 0, localPrefix, 0, localPrefix.length())) {
            return t.substring(localPrefix.length()).trim();
        }
        return t;
    }

    private void refreshCachedProviderDefaults() {
        cachedDefaultOpenai = normalizeDefaultModelLine("openai",
                defaultOpenaiModelField != null ? defaultOpenaiModelField.getText() : null, "openai/gpt-4o-mini");
        cachedDefaultGemini = normalizeDefaultModelLine("gemini",
                defaultGeminiModelField != null ? defaultGeminiModelField.getText() : null, "gemini/gemini-2.0-flash-lite");
        cachedDefaultClaude = normalizeDefaultModelLine("claude",
                defaultClaudeModelField != null ? defaultClaudeModelField.getText() : null, "claude/claude-3-5-haiku-latest");
        cachedDefaultOpenrouter = normalizeDefaultModelLine("openrouter",
                defaultOpenrouterModelField != null ? defaultOpenrouterModelField.getText() : null,
                "openrouter/mistralai/mistral-7b-instruct");
        cachedDefaultXai = normalizeDefaultModelLine("xai",
                defaultXaiModelField != null ? defaultXaiModelField.getText() : null, "xai/grok-4-1-fast-non-reasoning");
        cachedDefaultLocal = normalizeDefaultModelLine("local",
                defaultLocalModelCombo != null ? getDefaultLocalModelComboText() : null, "local/gemma4:e4b");
    }

    private static String passiveContentTypeLower(HttpResponse response) {
        for (HttpHeader h : response.headers()) {
            if ("Content-Type".equalsIgnoreCase(h.name())) {
                return h.value().toLowerCase(Locale.ROOT);
            }
        }
        return "";
    }

    private static boolean passiveBodyLooksTextual(HttpResponse response) {
        String body = response.bodyToString();
        if (body == null) {
            return false;
        }
        String trim = body.trim();
        if (trim.isEmpty()) {
            return false;
        }
        char c = trim.charAt(0);
        return c == '{' || c == '[' || c == '<' || c == '"' || Character.isLetter(c);
    }

    /**
     * Shared body/path/content-type filters. When {@code require2xxSuccess} is false, non-2xx responses are allowed
     * so issues that depend on error status lines still reach the LLM.
     */
    private boolean shouldScheduleAiTrafficContentFilters(HttpRequestResponse rr, boolean require2xxSuccess) {
        if (rr == null) {
            return false;
        }
        HttpRequest req = rr.request();
        HttpResponse res = rr.response();
        if (req == null || res == null) {
            return false;
        }
        if (require2xxSuccess && !res.isStatusCodeClass(StatusCodeClass.CLASS_2XX_SUCCESS)) {
            return false;
        }
        int maxBytes = passiveMaxResponseBytes;
        if (res.body().length() > maxBytes) {
            return false;
        }
        String path = req.path();
        if (path != null) {
            String pl = path.toLowerCase(Locale.ROOT);
            if (pl.endsWith(".png") || pl.endsWith(".jpg") || pl.endsWith(".jpeg") || pl.endsWith(".gif")
                    || pl.endsWith(".webp") || pl.endsWith(".ico") || pl.endsWith(".woff") || pl.endsWith(".woff2")
                    || pl.endsWith(".ttf") || pl.endsWith(".eot") || pl.endsWith(".mp4") || pl.endsWith(".mp3")
                    || pl.endsWith(".pdf") || pl.endsWith(".zip") || pl.endsWith(".css") || pl.endsWith(".map")
                    || pl.endsWith(".js") || pl.endsWith(".mjs") || pl.endsWith(".cjs")) {
                return false;
            }
        }
        String ct = passiveContentTypeLower(res);
        if (ct.contains("image/") || ct.contains("font/") || ct.contains("video/") || ct.contains("audio/")
                || ct.contains("application/octet-stream") || ct.contains("javascript") || ct.contains("ecmascript")
                || ct.contains("text/css")) {
            return false;
        }
        if (ct.contains("json") || ct.contains("html") || ct.contains("xml")
                || ct.contains("text/")) {
            return true;
        }
        return ct.isEmpty() && res.body().length() <= 64 * 1024 && passiveBodyLooksTextual(res);
    }

    private boolean shouldSchedulePassiveAiAudit(HttpRequestResponse rr) {
        if (!shouldScheduleAiTrafficContentFilters(rr, true)) {
            return false;
        }
        HttpRequest req = rr.request();
        if (passiveAiInScopeOnly && !api.scope().isInScope(req.url())) {
            return false;
        }
        return true;
    }

    private void migrateDualModelPreferencesIfNeeded() {
        String auto = api.persistence().preferences().getString(PREF_PREFIX + "selected_model_automatic");
        String manual = api.persistence().preferences().getString(PREF_PREFIX + "selected_model_manual");
        if (auto != null && manual != null) {
            return;
        }
        String legacy = api.persistence().preferences().getString(PREF_PREFIX + "selected_model");
        String fallback = legacy != null ? legacy : "Default";
        if (auto == null) {
            api.persistence().preferences().setString(PREF_PREFIX + "selected_model_automatic", fallback);
        }
        if (manual == null) {
            api.persistence().preferences().setString(PREF_PREFIX + "selected_model_manual", fallback);
        }
    }

    private void migratePassiveAiPreferencesIfNeeded() {
        Boolean scanner = api.persistence().preferences().getBoolean(PREF_PREFIX + "passive_ai_scanner_issues");
        Boolean allTraffic = api.persistence().preferences().getBoolean(PREF_PREFIX + "passive_ai_all_traffic");
        if (scanner != null || allTraffic != null) {
            return;
        }
        Boolean legacy = api.persistence().preferences().getBoolean(PREF_PREFIX + "passive_ai_enabled");
        api.persistence().preferences().setBoolean(PREF_PREFIX + "passive_ai_scanner_issues", true);
        api.persistence().preferences().setBoolean(PREF_PREFIX + "passive_ai_all_traffic", Boolean.TRUE.equals(legacy));
    }

    private void syncPassiveAiFlagsFromPreferences() {
        migratePassiveAiPreferencesIfNeeded();
        Boolean psi = api.persistence().preferences().getBoolean(PREF_PREFIX + "passive_ai_scanner_issues");
        Boolean pat = api.persistence().preferences().getBoolean(PREF_PREFIX + "passive_ai_all_traffic");
        passiveAiOnScannerIssues = psi == null || Boolean.TRUE.equals(psi);
        passiveAiAuditAllTraffic = Boolean.TRUE.equals(pat);
    }

    private void migrateProxyBrowserLocalAiPreferenceIfNeeded() {
        Boolean b = api.persistence().preferences().getBoolean(PREF_PREFIX + "proxy_browser_local_ai");
        if (b != null) {
            return;
        }
        api.persistence().preferences().setBoolean(PREF_PREFIX + "proxy_browser_local_ai", true);
    }

    private void syncProxyBrowserLocalAiFlagFromPreferences() {
        migrateProxyBrowserLocalAiPreferenceIfNeeded();
        Boolean b = api.persistence().preferences().getBoolean(PREF_PREFIX + "proxy_browser_local_ai");
        proxyBrowserLocalAiEnabled = b == null || Boolean.TRUE.equals(b);
    }

    private boolean selectedModelUsesLocalProvider() {
        String m = getAutomaticAuditModel();
        if (m == null || "Default".equals(m)) {
            return false;
        }
        String[] parts = m.split("/", 2);
        return parts.length >= 1 && "local".equals(parts[0]);
    }

    private boolean isReadyForProxyLocalAiAudit() {
        return selectedModelUsesLocalProvider()
                && localEndpointField != null
                && !localEndpointField.getText().trim().isEmpty();
    }

    private boolean isRequestToLocalLlmEndpoint(HttpRequest req) {
        if (localEndpointField == null) {
            return false;
        }
        String endpoint = localEndpointField.getText().trim();
        if (endpoint.isEmpty()) {
            return false;
        }
        try {
            URL u = new URL(endpoint.trim());
            String host = u.getHost();
            int urlPort = u.getPort();
            if (urlPort < 0) {
                urlPort = u.getDefaultPort();
            }
            HttpService svc = req.httpService();
            if (svc == null) {
                return false;
            }
            return host.equalsIgnoreCase(svc.host()) && urlPort == svc.port();
        } catch (Exception e) {
            return false;
        }
    }

    private String auditDedupKeyHostPath(HttpRequest req) {
        if (req == null) {
            return "";
        }
        String path = req.path();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        HttpService svc = req.httpService();
        String host = svc != null ? svc.host().toLowerCase(Locale.ROOT) : "";
        return req.method() + "\t" + host + "\t" + path;
    }

    private String buildCombinedScannerIssuesPreamble(List<AuditIssue> issues) {
        StringBuilder sb = new StringBuilder();
        sb.append("CONTEXT: Burp reported ").append(issues.size())
                .append(" scanner issue(s) for this HTTP exchange. Analyze holistically; weigh interactions between findings.\n\n");
        for (int i = 0; i < issues.size(); i++) {
            sb.append("--- Scanner issue ").append(i + 1).append(" ---\n");
            sb.append(buildScannerIssueDeepDivePreamble(issues.get(i)));
            sb.append("\n\n");
        }
        return sb.toString();
    }

    private static boolean sameScannerIssue(AuditIssue a, AuditIssue b) {
        if (a == b) {
            return true;
        }
        return Objects.equals(a.name(), b.name())
                && Objects.equals(a.detail(), b.detail())
                && Objects.equals(a.severity(), b.severity());
    }

    private void scheduleScannerIssueBatchFlush(String key, AuditIssue issue, HttpRequestResponse rr) {
        PendingScannerIssueBatch batch = pendingScannerIssueBatches.computeIfAbsent(key, k -> new PendingScannerIssueBatch());
        synchronized (batch) {
            boolean seen = false;
            for (AuditIssue ex : batch.issues) {
                if (sameScannerIssue(ex, issue)) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                batch.issues.add(issue);
            }
            batch.representativeRr = rr;
            if (batch.scheduledFlush != null) {
                batch.scheduledFlush.cancel(false);
            }
            batch.scheduledFlush = scannerIssueDebounceScheduler.schedule(() -> flushScannerIssueBatch(key), 750, TimeUnit.MILLISECONDS);
        }
    }

    private void flushScannerIssueBatch(String key) {
        PendingScannerIssueBatch batch = pendingScannerIssueBatches.remove(key);
        if (batch == null) {
            return;
        }
        final List<AuditIssue> issuesCopy;
        final HttpRequestResponse rr;
        synchronized (batch) {
            if (batch.issues.isEmpty()) {
                return;
            }
            issuesCopy = new ArrayList<>(batch.issues);
            rr = batch.representativeRr;
        }
        if (rr == null || rr.request() == null) {
            return;
        }
        final String preamble = buildCombinedScannerIssuesPreamble(issuesCopy);
        log("Scanner-issue AI audit queued (batched " + issuesCopy.size() + "): " + key, LogCategory.GENERAL);
        appendDashboardActivity("Automatic AI audit (Scanner issues, batched " + issuesCopy.size() + ") — " + truncateForIssueTitle(key, 200));
        SwingUtilities.invokeLater(() -> processAuditRequest(rr, null, false, preamble, true));
    }

    /**
     * Limit automatic Proxy LLM audits so a busy site cannot flood Burp's EDT / local model.
     */
    private boolean allowAnotherProxyAiAudit() {
        long now = System.currentTimeMillis();
        long start = proxyAiWindowStartMs;
        if (now - start > PROXY_AI_WINDOW_MS) {
            proxyAiWindowStartMs = now;
            proxyAiWindowCount.set(0);
        }
        return proxyAiWindowCount.incrementAndGet() <= PROXY_AI_MAX_PER_WINDOW;
    }

    /**
     * EDT: invoked after {@link HttpHandler} sees Proxy traffic; skips unless local model + endpoint are configured.
     */
    private void considerQueueProxyBrowserAiAudit(HttpRequestResponse rr) {
        if (isShuttingDown || !proxyBrowserLocalAiEnabled) {
            return;
        }
        if (!isReadyForProxyLocalAiAudit()) {
            return;
        }
        if (rr == null || rr.request() == null || rr.response() == null) {
            return;
        }
        HttpRequest req = rr.request();
        if (isRequestToLocalLlmEndpoint(req)) {
            return;
        }
        if (passiveAiInScopeOnly && !api.scope().isInScope(req.url())) {
            return;
        }
        if (!shouldScheduleAiTrafficContentFilters(rr, false)) {
            return;
        }
        if (!allowAnotherProxyAiAudit()) {
            return;
        }
        String dedupKey = auditDedupKeyHostPath(req);
        if (!proxyBrowserAiDedupKeys.add(dedupKey)) {
            return;
        }
        if (proxyBrowserAiDedupKeys.size() > PASSIVE_AUDIT_DEDUP_MAX_KEYS) {
            proxyBrowserAiDedupKeys.clear();
        }
        log("Proxy browser AI audit queued: " + req.url(), LogCategory.GENERAL);
        processAuditRequest(rr, null, false, null, true);
    }

    /**
     * Burp notifies this when any Scanner issue is added. We queue an LLM audit with the same deep-dive preamble as the
     * context-menu flow, skipping our own {@link AIAuditIssue}s to avoid feedback loops.
     */
    private void onNewScannerIssueForAiAudit(AuditIssue issue) {
        if (isShuttingDown || !passiveAiOnScannerIssues) {
            return;
        }
        if (isExtensionGeneratedIssue(issue)) {
            return;
        }
        List<HttpRequestResponse> rrs = resolveTrafficForIssue(issue);
        if (rrs.isEmpty()) {
            return;
        }
        for (HttpRequestResponse rr : rrs) {
            HttpRequest req = rr.request();
            if (passiveAiInScopeOnly && !api.scope().isInScope(req.url())) {
                continue;
            }
            if (!shouldScheduleAiTrafficContentFilters(rr, false)) {
                continue;
            }
            String key = auditDedupKeyHostPath(req);
            scheduleScannerIssueBatchFlush(key, issue, rr);
        }
    }

    private boolean isExtensionGeneratedIssue(AuditIssue issue) {
        if (issue == null) {
            return false;
        }
        if (issue instanceof AIAuditIssue) {
            return true;
        }
        String name = issue.name();
        if (name != null) {
            String n = name.toLowerCase(Locale.ROOT);
            if (n.startsWith("ai audit:") || n.startsWith("ai investigate / poc")) {
                return true;
            }
        }
        String detail = issue.detail();
        if (detail != null) {
            String d = detail.toLowerCase(Locale.ROOT);
            if (d.contains("__issue identified by ai auditor__")
                    || d.contains("**ai investigation (poc / exploitation)**")) {
                return true;
            }
        }
        return false;
    }



    private void showError(String message, Throwable error) {
        String errorMessage = message;
        if (error != null && error.getMessage() != null) {
            errorMessage += ": " + error.getMessage();
        }
        api.logging().logToError(errorMessage);
        api.logging().raiseErrorEvent(errorMessage);
    }

	private void logDebug(String message, Throwable error) {
		String debugMessage = "[DEBUG] " + message;
        if (error != null && error.getMessage() != null) {
            debugMessage += ": " + error.getMessage();
        }
		api.logging().logToOutput(debugMessage); // Prints to Burp's Output tab
		api.logging().raiseDebugEvent(debugMessage); // Sends to Burp's Event Log
	}


@Override
public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
    if (isShuttingDown || baseRequestResponse == null || baseRequestResponse.request() == null || auditInsertionPoint == null) {
        return AuditResult.auditResult(Collections.emptyList());
    }
    HttpRequest baseRequest = baseRequestResponse.request();
    if (passiveAiInScopeOnly && !api.scope().isInScope(baseRequest.url())) {
        return AuditResult.auditResult(Collections.emptyList());
    }

    List<AuditIssue> issues = new ArrayList<>();
    AtomicInteger insertionRequestCount = new AtomicInteger(0);
    issues.addAll(runTimingSqliChecks(baseRequestResponse, baseRequest, auditInsertionPoint, insertionRequestCount));
    issues.addAll(runOobChecks(baseRequestResponse, baseRequest, auditInsertionPoint, insertionRequestCount));
    return AuditResult.auditResult(issues);
}

private List<AuditIssue> runTimingSqliChecks(HttpRequestResponse baseRequestResponse, HttpRequest baseRequest, AuditInsertionPoint insertionPoint,
        AtomicInteger insertionRequestCount) {
    List<AuditIssue> issues = new ArrayList<>();
    HttpService fallbackService = baseRequest != null ? baseRequest.httpService() : null;
    if (fallbackService == null || fallbackService.host() == null || fallbackService.host().isEmpty()) {
        logActiveNullServiceThrottled("Timing SQLi check skipped: base request has no HTTP service.");
        return issues;
    }
    String[] timingPayloads = {
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR SLEEP(5)-- ",
            "'||(SELECT pg_sleep(5))--"
    };
    List<Long> baseline = measureTimings(baseRequest, insertionRequestCount, 2);
    if (baseline.size() < 2) {
        return issues;
    }
    long baselineMedian = medianMs(baseline);
    for (String payload : timingPayloads) {
        try {
            HttpRequest requestWithPayload = insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
            requestWithPayload = ensureHttpService(requestWithPayload, fallbackService);
            List<Long> injected = measureTimings(requestWithPayload, insertionRequestCount, 2);
            if (injected.size() < 2) {
                break;
            }
            long injectedMedian = medianMs(injected);
            long delta = injectedMedian - baselineMedian;
            if (injectedMedian >= TIMING_SQLI_DELAY_MS && delta >= TIMING_SQLI_THRESHOLD_MS) {
                String detail = "Observed significant delay after SQL timing payload.\n\n"
                        + "- Payload: `" + payload + "`\n"
                        + "- Baseline median: `" + baselineMedian + " ms`\n"
                        + "- Injected median: `" + injectedMedian + " ms`\n"
                        + "- Delta: `" + delta + " ms`\n"
                        + "- Threshold: `" + TIMING_SQLI_THRESHOLD_MS + " ms`\n\n"
                        + "This may indicate blind/time-based SQL injection.";
                issues.add(new AIAuditIssue.Builder()
                        .name("Possible time-based SQL injection (active check)")
                        .detail(detail)
                        .endpoint(baseRequest.url().toString())
                        .severity(AuditIssueSeverity.MEDIUM)
                        .confidence(delta >= (TIMING_SQLI_THRESHOLD_MS + 1500) ? AuditIssueConfidence.CERTAIN : AuditIssueConfidence.FIRM)
                        .requestResponses(Collections.singletonList(baseRequestResponse))
                        .modelUsed("scanner/active-check")
                        .build());
                break;
            }
        } catch (Exception e) {
            log("Timing SQLi check failed: " + e.getMessage(), LogCategory.GENERAL);
        }
    }
    return issues;
}

private List<AuditIssue> runOobChecks(HttpRequestResponse baseRequestResponse, HttpRequest baseRequest, AuditInsertionPoint insertionPoint,
        AtomicInteger insertionRequestCount) {
    List<AuditIssue> issues = new ArrayList<>();
    if (collaboratorClient == null) {
        return issues;
    }
    String collabPayload = collaboratorClient.generatePayload().toString();
    issues.addAll(runSingleOobCheck(baseRequestResponse, baseRequest, insertionPoint, insertionRequestCount,
            "OOB SSRF", "http://" + collabPayload + "/ssrf", collabPayload));
    issues.addAll(runSingleOobCheck(baseRequestResponse, baseRequest, insertionPoint, insertionRequestCount, "OOB XXE",
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"http://" + collabPayload + "/xxe\">]><r>&xxe;</r>",
            collabPayload));
    return issues;
}

private List<AuditIssue> runSingleOobCheck(HttpRequestResponse baseRequestResponse, HttpRequest baseRequest, AuditInsertionPoint insertionPoint,
        AtomicInteger insertionRequestCount, String checkName, String payload, String collabPayload) {
    List<AuditIssue> issues = new ArrayList<>();
    try {
        HttpRequest requestWithPayload = insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
        requestWithPayload = ensureHttpService(requestWithPayload, baseRequest != null ? baseRequest.httpService() : null);
        HttpRequestResponse sent = sendActiveAuditRequest(requestWithPayload, insertionRequestCount);
        if (sent == null) {
            return issues;
        }
        List<Interaction> interactions = pollCollaboratorInteractions(collabPayload);
        if (!interactions.isEmpty()) {
            String detail = "Out-of-band interaction confirmed via Burp Collaborator.\n\n"
                    + "- Check: `" + checkName + "`\n"
                    + "- Collaborator payload: `" + collabPayload + "`\n"
                    + "- Interaction count: `" + interactions.size() + "`\n\n"
                    + "This indicates server-side processing that triggered an external callback.";
            issues.add(new AIAuditIssue.Builder()
                    .name(checkName + " (active OOB check)")
                    .detail(detail)
                    .endpoint(baseRequest.url().toString())
                    .severity(AuditIssueSeverity.HIGH)
                    .confidence(AuditIssueConfidence.CERTAIN)
                    .requestResponses(Collections.singletonList(sent))
                    .modelUsed("scanner/active-check")
                    .build());
        }
    } catch (Exception e) {
        log(checkName + " check failed: " + e.getMessage(), LogCategory.GENERAL);
    }
    return issues;
}

private List<Interaction> pollCollaboratorInteractions(String payload) {
    for (int i = 0; i < OOB_POLL_ROUNDS; i++) {
        try {
            List<Interaction> interactions = collaboratorClient.getInteractions(
                    InteractionFilter.interactionPayloadFilter(payload));
            if (interactions != null && !interactions.isEmpty()) {
                return interactions;
            }
            Thread.sleep(OOB_POLL_SLEEP_MS);
        } catch (Exception e) {
            log("Collaborator poll failed: " + e.getMessage(), LogCategory.GENERAL);
            break;
        }
    }
    return Collections.emptyList();
}

private long sendForElapsedMs(HttpRequest request, AtomicInteger insertionRequestCount) throws Exception {
    long start = System.nanoTime();
    HttpRequestResponse rr = sendActiveAuditRequest(request, insertionRequestCount);
    if (rr == null) {
        return -1L;
    }
    long elapsedNs = System.nanoTime() - start;
    return TimeUnit.NANOSECONDS.toMillis(elapsedNs);
}

private List<Long> measureTimings(HttpRequest request, AtomicInteger insertionRequestCount, int repeats) {
    List<Long> samples = new ArrayList<>();
    for (int i = 0; i < repeats; i++) {
        try {
            long ms = sendForElapsedMs(request, insertionRequestCount);
            if (ms < 0) {
                break;
            }
            samples.add(ms);
        } catch (Exception e) {
            log("Timing sample failed: " + e.getMessage(), LogCategory.GENERAL);
            break;
        }
    }
    return samples;
}

private long medianMs(List<Long> values) {
    if (values == null || values.isEmpty()) {
        return 0L;
    }
    List<Long> copy = new ArrayList<>(values);
    Collections.sort(copy);
    int n = copy.size();
    if (n % 2 == 1) {
        return copy.get(n / 2);
    }
    return (copy.get((n / 2) - 1) + copy.get(n / 2)) / 2L;
}

private HttpRequestResponse sendActiveAuditRequest(HttpRequest request, AtomicInteger insertionRequestCount) throws Exception {
    if (request == null) {
        return null;
    }
    HttpService svc = request.httpService();
    if (svc == null || svc.host() == null || svc.host().isEmpty()) {
        logActiveNullServiceThrottled("Active check skipped: HTTP service cannot be resolved for generated request.");
        return null;
    }
    if (!tryConsumeActiveBudget(request, insertionRequestCount)) {
        return null;
    }
    return api.http().sendRequest(request);
}

private boolean tryConsumeActiveBudget(HttpRequest request, AtomicInteger insertionRequestCount) {
    if (request == null) {
        return false;
    }
    HttpService svc = request.httpService();
    if (svc == null || svc.host() == null || svc.host().isEmpty()) {
        return false;
    }
    if (insertionRequestCount.incrementAndGet() > ACTIVE_SCAN_MAX_REQUESTS_PER_INSERTION) {
        return false;
    }
    String host = svc.host().toLowerCase(Locale.ROOT);
    ActiveHostRequestBudget budget = activeHostRequestBudgets.computeIfAbsent(host, h -> new ActiveHostRequestBudget());
    if (!budget.tryConsumeOne()) {
        return false;
    }
    return true;
}

private HttpRequest ensureHttpService(HttpRequest request, HttpService fallbackService) {
    if (request == null) {
        return null;
    }
    HttpService svc = request.httpService();
    if (svc != null && svc.host() != null && !svc.host().isEmpty()) {
        return request;
    }
    if (fallbackService == null || fallbackService.host() == null || fallbackService.host().isEmpty()) {
        return request;
    }
    try {
        return HttpRequest.httpRequest(fallbackService, request.toString());
    } catch (Exception e) {
        logActiveNullServiceThrottled("Could not apply fallback HTTP service to generated request: " + e.getMessage());
        return request;
    }
}

private void logActiveNullServiceThrottled(String message) {
    long now = System.currentTimeMillis();
    if (now - lastActiveNullServiceLogMs >= 30_000L) {
        lastActiveNullServiceLogMs = now;
        log(message, LogCategory.GENERAL);
    }
}

private static final class ActiveHostRequestBudget {
    private long windowStartMs = System.currentTimeMillis();
    private int used = 0;

    synchronized boolean tryConsumeOne() {
        long now = System.currentTimeMillis();
        if (now - windowStartMs > ACTIVE_SCAN_HOST_WINDOW_MS) {
            windowStartMs = now;
            used = 0;
        }
        if (used >= ACTIVE_SCAN_MAX_REQUESTS_PER_HOST_WINDOW) {
            return false;
        }
        used++;
        return true;
    }
}

@Override
public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
    if (isShuttingDown || !passiveAiAuditAllTraffic) {
        return AuditResult.auditResult(Collections.emptyList());
    }
    if (!shouldSchedulePassiveAiAudit(baseRequestResponse)) {
        return AuditResult.auditResult(Collections.emptyList());
    }
    HttpRequest req = baseRequestResponse.request();
    String dedupKey = auditDedupKeyHostPath(req);
    if (!passiveAuditDedupKeys.add(dedupKey)) {
        return AuditResult.auditResult(Collections.emptyList());
    }
    if (passiveAuditDedupKeys.size() > PASSIVE_AUDIT_DEDUP_MAX_KEYS) {
        passiveAuditDedupKeys.clear();
    }
    log("Passive AI audit queued: " + req.url(), LogCategory.GENERAL);
    appendDashboardActivity("Passive AI audit queued — " + truncateForIssueTitle(req.url(), 200));
    SwingUtilities.invokeLater(() -> processAuditRequest(baseRequestResponse, null, false, null, true));
    return AuditResult.auditResult(Collections.emptyList());
}

@Override
public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
    if (isExtensionGeneratedIssue(newIssue)) {
        String newName = newIssue.name() != null ? newIssue.name() : "";
        String existingName = existingIssue.name() != null ? existingIssue.name() : "";
        String newBase = newIssue.baseUrl() != null ? newIssue.baseUrl() : "";
        String existingBase = existingIssue.baseUrl() != null ? existingIssue.baseUrl() : "";
        if (newName.equals(existingName) && newBase.equals(existingBase)) {
            return ConsolidationAction.KEEP_NEW;
        }
    }
    if (newIssue.name().equals(existingIssue.name()) &&
        newIssue.detail().equals(existingIssue.detail()) &&
        newIssue.severity().equals(existingIssue.severity())) {
        return ConsolidationAction.KEEP_EXISTING;
    }
    return ConsolidationAction.KEEP_BOTH;
}

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        if (isShuttingDown || !proxyBrowserLocalAiEnabled) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        if (responseReceived == null) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        boolean fromProxy = responseReceived.toolSource().isFromTool(ToolType.PROXY);
        boolean fromRepeater = proxyIncludeRepeater && responseReceived.toolSource().isFromTool(ToolType.REPEATER);
        if (!fromProxy && !fromRepeater) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        HttpRequest initiating = responseReceived.initiatingRequest();
        if (initiating == null) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }
        final HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(initiating, responseReceived);
        SwingUtilities.invokeLater(() -> considerQueueProxyBrowserAiAudit(rr));
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private void testGeminiKeyCycling() {
        log("--- Starting Gemini Key Cycling Test ---", LogCategory.GENERAL);

        if (geminiApiKeys.isEmpty()) {
            log("No Gemini API keys loaded. Test cannot run.", LogCategory.GENERAL);
            return;
        }

        log("Total keys loaded: " + geminiApiKeys.size(), LogCategory.GENERAL);
        int initialIndex = currentGeminiKeyIndex.get();
        log("Initial key index: " + initialIndex, LogCategory.GENERAL);

        for (int i = 0; i < geminiApiKeys.size() * 2; i++) { // Cycle through the keys twice
            String currentKey = getNextGeminiApiKey(false); // Get current key without cycling
            log(String.format("Test Cycle %d: Current key (ends with...%s)", i + 1, currentKey.substring(currentKey.length() - 4)), LogCategory.GENERAL);
            
            // Simulate a failure, which causes a cycle
            log("Simulating rate-limit failure...", LogCategory.GENERAL);
            currentKey = getNextGeminiApiKey(true); // Cycle to the next key
            log(String.format("Test Cycle %d: Switched to new key (ends with...%s)", i + 1, currentKey.substring(currentKey.length() - 4)), LogCategory.GENERAL);
        }

        log("--- Gemini Key Cycling Test Finished ---", LogCategory.GENERAL);
    }

    private void resetModelsToDefault() {
        SwingUtilities.invokeLater(() -> {
            availableModels.clear();
            availableModels.add("Default");
            availableModels.add("local/local-llm (LM Studio)");
            availableModels.add("claude/claude-opus-4-6");
            availableModels.add("claude/claude-3-opus-latest");
            availableModels.add("claude/claude-3-5-sonnet-latest");
            availableModels.add("claude/claude-3-5-haiku-latest");
            availableModels.add("gemini/gemini-2.5-pro");
            availableModels.add("gemini/gemini-2.5-flash");
            availableModels.add("gemini/gemini-2.0-flash");
            availableModels.add("gemini/gemini-2.0-flash-lite");
            availableModels.add("openai/gpt-4o-mini");
            availableModels.add("openai/gpt-4o");
            availableModels.add("openrouter/openai/o1-preview");
            availableModels.add("openrouter/openai/o1-mini");
            availableModels.add("openrouter/mistralai/mistral-7b-instruct");
            availableModels.add("xai/grok-4-1-fast-non-reasoning");
            availableModels.add("xai/grok-4-1-fast-reasoning");
            availableModels.add("xai/grok-4.20-0309-non-reasoning");
            availableModels.add("xai/grok-4.20-0309-reasoning");
            applyModelFilter(); // Apply filter after resetting available models
            log("Model list has been reset to defaults.", LogCategory.GENERAL);
        });
    }

    private CompletableFuture<List<String>> fetchOpenRouterModels(String apiKey) {
        return CompletableFuture.supplyAsync(() -> {
            List<String> openrouterModels = new ArrayList<>();
            if (apiKey.isEmpty()) {
                log("OpenRouter API key is empty. Skipping model fetch.", LogCategory.GENERAL);
                return openrouterModels;
            }

            try {
                URL url = new URL("https://openrouter.ai/api/v1/models");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(60000);

                int responseCode = conn.getResponseCode();
                if (responseCode == 200) {
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                        StringBuilder response = new StringBuilder();
                        String line;
                        while ((line = reader.readLine()) != null) {
                            response.append(line);
                        }
                        JSONObject jsonResponse = new JSONObject(response.toString());
                        JSONArray data = jsonResponse.getJSONArray("data");
                        for (int i = 0; i < data.length(); i++) {
                            JSONObject model = data.getJSONObject(i);
                            String id = model.getString("id");
                            // Filter for useful text-based models, adjust as needed
                            if (id.contains("text") || id.contains("chat") || id.contains("instruct") || id.contains("gpt") || id.contains("claude") || id.contains("gemini") || id.contains("mistral") || id.contains("llama")) {
                                openrouterModels.add("openrouter/" + id);
                            }
                        }
                        log("Successfully fetched OpenRouter models.", LogCategory.GENERAL);
                    }
                } else {
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                        StringBuilder errorResponse = new StringBuilder();
                        String line;
                        while ((line = reader.readLine()) != null) {
                            errorResponse.append(line);
                        }
                        api.logging().logToError("Failed to fetch OpenRouter models. Response Code: " + responseCode + ", Error: " + errorResponse.toString());
                    }
                }
            } catch (Exception e) {
                api.logging().logToError("Error fetching OpenRouter models: " + e.getMessage());
            }
            return openrouterModels;
        });
    }

    private void restoreDropdownSelection(JComboBox<String> box, String previous) {
        if (previous == null || box == null) {
            return;
        }
        for (int i = 0; i < box.getItemCount(); i++) {
            if (previous.equals(box.getItemAt(i))) {
                box.setSelectedIndex(i);
                return;
            }
        }
    }

    private void repopulateFilteredModelDropdown(JComboBox<String> modelDropdown) {
        String filterText = filterModelsField.getText().toLowerCase();
        String[] keywords = filterText.split(",");

        modelDropdown.removeAllItems();
        modelDropdown.addItem("Default");
        modelDropdown.addItem("local/local-llm (LM Studio)");

        List<String> filteredModels = new ArrayList<>();
        for (String model : availableModels) {
            if ("Default".equals(model) || "local/local-llm (LM Studio)".equals(model)) {
                continue;
            }

            boolean matchesFilter = true;
            if (!filterText.isEmpty()) {
                for (String keyword : keywords) {
                    if (!keyword.trim().isEmpty() && model.toLowerCase().contains(keyword.trim())) {
                        matchesFilter = false;
                        break;
                    }
                }
            }
            if (matchesFilter) {
                filteredModels.add(model);
            }
        }

        Collections.sort(filteredModels);
        for (String model : filteredModels) {
            modelDropdown.addItem(model);
        }
    }

    private void applyModelFilter() {
        if (automaticAuditModelDropdown == null || manualInvestigationModelDropdown == null) {
            return;
        }
        String prevAuto = (String) automaticAuditModelDropdown.getSelectedItem();
        String prevManual = (String) manualInvestigationModelDropdown.getSelectedItem();
        repopulateFilteredModelDropdown(automaticAuditModelDropdown);
        repopulateFilteredModelDropdown(manualInvestigationModelDropdown);
        restoreDropdownSelection(automaticAuditModelDropdown, prevAuto);
        restoreDropdownSelection(manualInvestigationModelDropdown, prevManual);
    }
			
			
    private void fetchLatestModels() {
        log("Fetching latest models...", LogCategory.GENERAL);
        CompletableFuture.runAsync(() -> {
            try {
                availableModels.clear();
                availableModels.add("Default"); // Always keep Default option at the top

                // Fetch models from all providers concurrently
                CompletableFuture<List<String>> openaiFuture = fetchOpenAIModels(new String(openaiKeyField.getPassword()));
                CompletableFuture<List<String>> geminiFuture = fetchGeminiModels(geminiKeyField.getText().split("\n")[0].trim());
                CompletableFuture<List<String>> claudeFuture = fetchClaudeModels(new String(claudeKeyField.getPassword()));
                CompletableFuture<List<String>> openrouterFuture = fetchOpenRouterModels(new String(openrouterKeyField.getPassword()));
                CompletableFuture<List<String>> xaiFuture = fetchXaiModels(new String(xaiKeyField.getPassword()));
                CompletableFuture<List<String>> localModelsFuture = CompletableFuture.supplyAsync(
                        this::fetchLocalOpenAiModelsList, threadPoolManager.getExecutor());

                // Wait for all futures to complete
                CompletableFuture.allOf(openaiFuture, geminiFuture, claudeFuture, openrouterFuture, xaiFuture, localModelsFuture).join();

                // Collect results and add to availableModels
                try {
                    availableModels.addAll(openaiFuture.get());
                } catch (Exception e) {
                    log("Failed to fetch OpenAI models: " + e.getMessage(), LogCategory.GENERAL);
                }
                try {
                    availableModels.addAll(geminiFuture.get());
                } catch (Exception e) {
                    log("Failed to fetch Gemini models: " + e.getMessage(), LogCategory.GENERAL);
                }
                try {
                    availableModels.addAll(claudeFuture.get());
                } catch (Exception e) {
                    log("Failed to fetch Claude models: " + e.getMessage(), LogCategory.GENERAL);
                }
                try {
                    availableModels.addAll(openrouterFuture.get());
                } catch (Exception e) {
                    log("Failed to fetch OpenRouter models: " + e.getMessage(), LogCategory.GENERAL);
                }
                try {
                    availableModels.addAll(xaiFuture.get());
                } catch (Exception e) {
                    log("Failed to fetch xAI models: " + e.getMessage(), LogCategory.GENERAL);
                }

                List<String> localOpenAiModelIds = new ArrayList<>();
                try {
                    localOpenAiModelIds.addAll(localModelsFuture.get());
                } catch (Exception e) {
                    log("Failed to fetch local LLM /v1/models list: " + e.getMessage(), LogCategory.GENERAL);
                }

                // Sort models alphabetically, excluding "Default" and "local-llm (LM Studio)"
                List<String> sortedModels = new ArrayList<>();
                for (String model : availableModels) {
                    if (!"Default".equals(model) && !"local/local-llm (LM Studio)".equals(model)) {
                        sortedModels.add(model);
                    }
                }
                Collections.sort(sortedModels);

                // Clear and re-add models to availableModels in sorted order
                availableModels.clear();
                availableModels.add("Default"); // Always add Default first
                availableModels.add("local/local-llm (LM Studio)"); // Always add local-llm last
                availableModels.addAll(sortedModels);

                final List<String> localIdsForUi = localOpenAiModelIds;
                SwingUtilities.invokeLater(() -> {
                    applyModelFilter(); // Apply filter after updating the full list
                    mergeLocalModelIdsIntoDropdown(localIdsForUi);
                    log("Model list updated with the latest models.", LogCategory.GENERAL);
                });

            } catch (Exception e) {
                log("An error occurred while fetching the latest models: " + e.getMessage(), LogCategory.GENERAL);
            }
        }, threadPoolManager.getExecutor());
    }

    /** Grok chat / language models only (excludes image, video, embedding SKUs from the models list). */
    private static boolean isXaiTextChatModelId(String id) {
        if (id == null) {
            return false;
        }
        String lower = id.toLowerCase();
        if (!lower.startsWith("grok")) {
            return false;
        }
        if (lower.contains("imagine") || lower.contains("embedding") || lower.contains("tts") || lower.contains("video")) {
            return false;
        }
        return true;
    }

    private CompletableFuture<List<String>> fetchXaiModels(String apiKey) {
        return CompletableFuture.supplyAsync(() -> {
            List<String> models = new ArrayList<>();
            if (apiKey == null || apiKey.isEmpty()) {
                return models;
            }
            try {
                URL url = new URL("https://api.x.ai/v1/models");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(60000);

                if (conn.getResponseCode() == 200) {
                    try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                        String inputLine;
                        StringBuilder content = new StringBuilder();
                        while ((inputLine = in.readLine()) != null) {
                            content.append(inputLine);
                        }
                        JSONObject jsonResponse = new JSONObject(content.toString());
                        JSONArray data = jsonResponse.getJSONArray("data");
                        for (int i = 0; i < data.length(); i++) {
                            String modelId = data.getJSONObject(i).getString("id");
                            if (isXaiTextChatModelId(modelId)) {
                                models.add("xai/" + modelId);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log("Error fetching xAI models: " + e.getMessage(), LogCategory.GENERAL);
            }
            return models;
        });
    }

    private CompletableFuture<List<String>> fetchOpenAIModels(String apiKey) {
        return CompletableFuture.supplyAsync(() -> {
            List<String> models = new ArrayList<>();
            if (apiKey.isEmpty()) {
                return models; // No API key, no models
            }
            try {
                URL url = new URL("https://api.openai.com/v1/models");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);

                if (conn.getResponseCode() == 200) {
                    try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                        String inputLine;
                        StringBuilder content = new StringBuilder();
                        while ((inputLine = in.readLine()) != null) {
                            content.append(inputLine);
                        }
                        JSONObject jsonResponse = new JSONObject(content.toString());
                        JSONArray data = jsonResponse.getJSONArray("data");
                        for (int i = 0; i < data.length(); i++) {
                            String modelId = data.getJSONObject(i).getString("id");
                            if (modelId.startsWith("gpt-") && (modelId.contains("turbo") || modelId.contains("4o") || modelId.contains("3.5"))) {
                                String formattedModelId = "openai/" + modelId;
                                models.add(formattedModelId);
                                log("Added OpenAI model: " + formattedModelId, LogCategory.GENERAL);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log("Error fetching OpenAI models: " + e.getMessage(), LogCategory.GENERAL);
            }
            return models;
        });
    }

    private CompletableFuture<List<String>> fetchGeminiModels(String apiKey) {
        return CompletableFuture.supplyAsync(() -> {
            List<String> models = new ArrayList<>();
            if (apiKey == null || apiKey.isEmpty()) {
                return models;
            }
            try {
                URL url = new URL("https://generativelanguage.googleapis.com/v1beta/models?key=" + apiKey);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");

                if (conn.getResponseCode() == 200) {
                    try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                        String inputLine;
                        StringBuilder content = new StringBuilder();
                        while ((inputLine = in.readLine()) != null) {
                            content.append(inputLine);
                        }
                        JSONObject jsonResponse = new JSONObject(content.toString());
                        JSONArray data = jsonResponse.getJSONArray("models");
                        for (int i = 0; i < data.length(); i++) {
                            String modelId = data.getJSONObject(i).getString("name");
                            if (modelId.contains("gemini")) { // Filter for Gemini models
                                models.add("gemini/" + modelId.replace("models/", ""));
                            }
                        }
                    }
                }
            } catch (Exception e) {
                log("Error fetching Gemini models: " + e.getMessage(), LogCategory.GENERAL);
            }
            return models;
        });
    }

    private CompletableFuture<List<String>> fetchClaudeModels(String apiKey) {
        return CompletableFuture.supplyAsync(() -> {
            // Claude API does not have a public endpoint to list models.
            // Returning a hardcoded list of known useful models.
            List<String> models = new ArrayList<>();
            models.add("claude/claude-opus-4-6");
            models.add("claude/claude-3-opus-20240229");
            models.add("claude/claude-3-sonnet-20240229");
            models.add("claude/claude-3-haiku-20240307");
            return models;
        });
    }

	private static int safeHash(Object... parts) {
		return Objects.hash(parts);     // null ➞ 0, no NPE
	}
    
}
