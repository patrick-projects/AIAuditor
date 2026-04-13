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

import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
 
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import burp.api.montoya.core.Range;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.core.ToolType;
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

    /** Anthropic Messages API: room for structured JSON findings without truncating mid-response. */
    private static final int CLAUDE_MAX_OUTPUT_TOKENS = 8192;

    private static final int PASSIVE_AUDIT_DEDUP_MAX_KEYS = 8000;
    private static final int DEFAULT_PASSIVE_MAX_BODY_KB = 256;

    private static final String PROXY_BROWSER_LOCAL_AI_TOOLTIP = "<html><body style='width:380px'>"
            + "Queues the same AI audit as manual scan for Burp’s <b>Proxy</b> (browser pace). Optionally add <b>Repeater</b> via the checkbox below. "
            + "Skips Scanner/crawler volume. Uses the <b>automatic audits</b> model + <b>Local LLM Endpoint</b> (LM Studio). "
            + "On Apple Silicon, <b>Gemma 3+</b> GGUF chat models are a strong default."
            + "</body></html>";

    private static final String LOCAL_LM_STUDIO_SETUP_TEXT =
            "Local LLM quick setup (browser traffic via Proxy):\n\n"
            + "1) Install LM Studio (lmstudio.ai), open the Search tab, download a small instruction-tuned GGUF "
            + "(Google Gemma 3 / Gemma 2 / future Gemma 4-class models work well on M-series Macs).\n"
            + "2) Load the model, open the Local Server tab, Start Server — note the URL (often http://127.0.0.1:1234/v1).\n"
            + "3) Paste that URL into \"Local LLM Endpoint\" on the left, set AI Model to local/local-llm or your loaded id, Save.\n"
            + "4) Enable \"Auto-audit browser (Proxy) → local LLM\" below. Browse through Burp; only Proxy traffic is analyzed.\n"
            + "5) Optional: point Burp’s proxy at 127.0.0.1:8080 and this extension at the LM Studio URL — "
            + "requests to the LM host are skipped to avoid feedback loops.\n"
            + "6) If you set \"Proxy (IP:Port)\" here for cloud APIs, localhost and your LM Studio host still connect directly "
            + "(Burp’s own upstream proxy setting does not affect that path).\n";
     
     private MontoyaApi api;
     private PersistedObject persistedData;
     private ThreadPoolManager threadPoolManager;
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
    private JTextField defaultLocalModelField;
    private String cachedDefaultOpenai = "openai/gpt-4o-mini";
    private String cachedDefaultGemini = "gemini/gemini-2.0-flash-lite";
    private String cachedDefaultClaude = "claude/claude-3-5-haiku-latest";
    private String cachedDefaultOpenrouter = "openrouter/mistralai/mistral-7b-instruct";
    private String cachedDefaultXai = "xai/grok-4-1-fast-non-reasoning";
    private String cachedDefaultLocal = "local/local-llm (LM Studio)";

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

    private static final class PendingScannerIssueBatch {
        final List<AuditIssue> issues = new ArrayList<>();
        volatile HttpRequestResponse representativeRr;
        volatile ScheduledFuture<?> scheduledFlush;
    }

    private final ConcurrentHashMap<String, PendingScannerIssueBatch> pendingScannerIssueBatches = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scannerIssueDebounceScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ai-auditor-scanner-issue-debounce");
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
				"You are an expert web application security researcher specializing in identifying high-impact vulnerabilities. " +
				"Analyze the provided HTTP request and response like a skilled bug bounty hunter, focusing on:\n\n" +
				"HIGH PRIORITY ISSUES:\n" +
				"1. Remote Code Execution (RCE) opportunities\n" +
				"2. SQL, NoSQL, command injection vectors\n" +
				"3. Authentication/Authorization bypasses\n" +
				"4. Insecure deserialization patterns\n" +
				"5. IDOR vulnerabilities (analyze ID patterns and access controls)\n" +
				"6. OAuth security issues (token exposure, implicit flow risks, state validation)\n" +
				"7. Sensitive information disclosure (tokens, credentials, internal paths)\n" +
				"8. XSS with demonstrable impact (focus on stored/reflected with actual risk)\n" +
				"9. CSRF in critical functions\n" +
				"10. Insecure cryptographic implementations\n" +
				"11. API endpoint security issues\n" +
				"12. Token entropy/predictability issues\n" +
				"Vulnerabilities that can directly be mapped to a CVE with public PoC and high-to-critical severity OWASP Top 10 vulnerabilities. \n\n",
				
				
				// Template 2:
				"ANALYSIS GUIDELINES:\n" +
				"- Prioritize issues likely to be missed by Nessus, Nuclei, and Burp Scanner\n" +
				"- Focus on vulnerabilities requiring deep response analysis\n" +
				"- Report API endpoints found in JS files as INFORMATION level only\n" +
				"- Ignore low-impact findings like missing headers (CSP, cookie flags, absence of security headers)\n" +
				"- Skip theoretical issues without clear evidence\n" +
				"- Provide specific evidence, reproduction steps or specifically crafted proof of concept\n" +
				"- Include detailed technical context for each finding\n\n" +
					   
				"SEVERITY CRITERIA:\n" +
				"HIGH: Immediate security impact (examples: RCE, auth bypass, MFA bypass, OAuth implicit flow, SSRF, critical data exposure, hardcoded secrets depending on context, command injection, insecure deserialization)\n" +
				"MEDIUM: Significant but not critical (examples: IDOR with limited scope, stored XSS, blind SSRF, blind injection, hardcoded secrets depending on context)\n" +
				"LOW: Valid security issue but limited impact (examples: Reflected XSS, HTML or CSS or DOM manipulation requiring user interaction)\n" +
				"INFORMATION: Useful security insights (API endpoints, potential attack surfaces)\n\n" +
				  
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
				"- Include specific paths, parameters, or patterns that indicate the vulnerability\n" +
				"- For OAuth issues, carefully analyze token handling and flows (especially implicit flow)\n" +
				"- For IDOR, analyze ID patterns and access control mechanisms\n" +
				"- For injection points, provide exact payload locations\n" +
				"- Ignore hardcoded Google client ID, content security policy, strict transport security not enforced, cookie scoped to parent domain, cacheable HTTPS response, browser XSS filter disabled\n" +
				"- For sensitive info disclosure, specify exact data exposed\n" +
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
    }

private void createMainTab() {
        mainPanel = new JPanel(new BorderLayout(8, 8));

        JTextArea quickStart = new JTextArea(
                "Three steps: (1) Connect tab — add a key or local LM, Validate, pick models, Save. "
                + "(2) Background tab — leave defaults unless you want browser/Proxy AI or \"all traffic\" (costly). "
                + "(3) Prompts tab — optional; skip until you want custom wording.",
                3, 68);
        quickStart.setEditable(false);
        quickStart.setLineWrap(true);
        quickStart.setWrapStyleWord(true);
        quickStart.setOpaque(false);
        quickStart.setBorder(BorderFactory.createEmptyBorder(4, 8, 8, 8));
        JPanel tipWrap = new JPanel(new BorderLayout());
        tipWrap.add(quickStart, BorderLayout.CENTER);
        tipWrap.setBorder(BorderFactory.createTitledBorder("How to use this screen"));

        JTabbedPane tabs = new JTabbedPane();
        tabs.setBorder(BorderFactory.createEmptyBorder(0, 4, 4, 4));
        tabs.addTab("Connect", wrapTabScroll(buildSetupProvidersPanel()));
        tabs.addTab("Background AI", wrapTabScroll(buildAutomationDefaultsPanel()));
        tabs.addTab("Prompts", wrapTabScroll(buildPromptsPanel()));
        tabs.addTab("Tuning", wrapTabScroll(buildAdvancedStatusPanel()));

        mainPanel.add(tipWrap, BorderLayout.NORTH);
        mainPanel.add(tabs, BorderLayout.CENTER);

        JScrollPane outerScroll = new JScrollPane(mainPanel);
        outerScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        outerScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        new javax.swing.Timer(1000, e -> updateStatusPanel()).start();

        api.userInterface().registerSuiteTab("AI Auditor", outerScroll);
    }

    private JScrollPane wrapTabScroll(JPanel content) {
        JScrollPane sp = new JScrollPane(content);
        sp.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        sp.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        return sp;
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

        JLabel connectHint = new JLabel("<html><div style='width:520px'>Add <b>one</b> cloud key <i>or</i> a local LM Studio URL, click <b>Validate</b>, then <b>Get Latest Models</b> and <b>Save Settings</b>.</div></html>");
        rgbc.gridy = 0;
        root.add(connectHint, rgbc);

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
        geminiKeyField = new JTextArea(5, 40);
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
        localEndpointLabel.setToolTipText("<html>LM Studio → Local Server → copy OpenAI base URL (e.g. <code>http://127.0.0.1:1234/v1</code>). "
                + "Load a Gemma-class or similar GGUF model before starting the server.</html>");
        cred.add(localEndpointLabel, gbc);
        localEndpointField = new JTextField(40);
        localEndpointField.setToolTipText(localEndpointLabel.getToolTipText());
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        cred.add(localEndpointField, gbc);
        row++;

        addApiKeyField(cred, gbc, row++, "Local LLM API Key (if required):", localKeyField = new JPasswordField(40), "local");

        rgbc.gridy = 1;
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
        JLabel autoModelLabel = new JLabel("Background / automatic:");
        autoModelLabel.setToolTipText("<html>Used for Scanner-issue follow-ups, Proxy/Repeater capture, and passive “all traffic”. "
                + "Often <code>local/…</code> or a small cheap cloud model.</html>");
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
        JLabel manualModelLabel = new JLabel("Manual (right-click, Explain, PoC):");
        manualModelLabel.setToolTipText("<html>Used when <b>you</b> start an action from the context menu. Pick a stronger model if you like.</html>");
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

        rgbc.gridy = 2;
        root.add(models, rgbc);

        saveButton = new JButton("Save Settings");
        saveButton.setToolTipText("Saves keys, models, prompts, and all other tabs.");
        saveButton.addActionListener(e -> saveSettings());
        JPanel saveWrap = new JPanel(new FlowLayout(FlowLayout.LEFT));
        saveWrap.add(saveButton);
        rgbc.gridy = 3;
        root.add(saveWrap, rgbc);

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

        JLabel bgHint = new JLabel("<html><div style='width:520px'>These only affect <b>automatic</b> LLM calls. "
                + "Right-click scans always work. Most users: leave the first two boxes on, leave <b>all passive traffic</b> off.</div></html>");
        rgbc.gridy = 0;
        root.add(bgHint, rgbc);

        JPanel autoBox = new JPanel(new GridBagLayout());
        autoBox.setBorder(BorderFactory.createTitledBorder("When to run the AI without you clicking"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.gridx = 0;
        int row = 0;

        passiveAiOnScannerIssuesCheckbox = new JCheckBox("After Burp Scanner finds an issue, ask the AI to review it (recommended)");
        passiveAiOnScannerIssuesCheckbox.setSelected(passiveAiOnScannerIssues);
        passiveAiAllTrafficCheckbox = new JCheckBox("Also send most passive HTTP to the AI (expensive — only if you mean it)");
        passiveAiAllTrafficCheckbox.setSelected(passiveAiAuditAllTraffic);
        proxyBrowserLocalAiCheckbox = new JCheckBox("Send browser Proxy traffic to a local model (LM Studio)");
        proxyBrowserLocalAiCheckbox.setSelected(proxyBrowserLocalAiEnabled);
        proxyBrowserLocalAiCheckbox.setToolTipText(PROXY_BROWSER_LOCAL_AI_TOOLTIP);
        proxyIncludeRepeaterCheckbox = new JCheckBox("Include Repeater responses (same rules as Proxy)");
        proxyIncludeRepeaterCheckbox.setSelected(proxyIncludeRepeater);
        proxyIncludeRepeaterCheckbox.setToolTipText("Queues LLM audits for HTTP responses sent from Repeater, not only the browser Proxy.");
        passiveAiInScopeCheckbox = new JCheckBox("Only in-scope URLs (Target scope)");
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

        JTextArea proxySetupGuideArea = new JTextArea(LOCAL_LM_STUDIO_SETUP_TEXT, 8, 42);
        proxySetupGuideArea.setEditable(false);
        proxySetupGuideArea.setLineWrap(true);
        proxySetupGuideArea.setWrapStyleWord(true);
        proxySetupGuideArea.setBackground(UIManager.getColor("Panel.background"));
        proxySetupGuideArea.setBorder(BorderFactory.createTitledBorder("Local LM Studio — step by step"));
        proxySetupGuideArea.setToolTipText("Step-by-step: LM Studio + Gemma-class model + Proxy-only auto-audits.");
        rgbc.gridy = 2;
        root.add(new JScrollPane(proxySetupGuideArea), rgbc);

        JPanel limits = new JPanel(new GridBagLayout());
        limits.setBorder(BorderFactory.createTitledBorder("Limits, proxy, and \"Default\" model IDs"));
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
        proxyLabel.setToolTipText("<html>Optional. Localhost and your Local LLM host stay <b>direct</b>.</html>");
        limits.add(proxyLabel, gbc);
        proxyField = new JTextField(24);
        proxyField.setToolTipText("<html>Optional HTTP proxy for <b>this extension’s</b> outbound API calls (OpenAI, Gemini, etc.). "
                + "Traffic to <b>localhost</b>, <b>127.0.0.1</b>, and your <b>Local LLM Endpoint</b> host is sent <b>direct</b> "
                + "so LM Studio still works when Burp uses a separate upstream proxy for browsing.</html>");
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        limits.add(proxyField, gbc);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        limits.add(new JLabel("<html>If a model dropdown says <b>Default</b>, the extension uses these IDs per provider:</html>"), gbc);
        gbc.gridwidth = 1;

        defaultOpenaiModelField = new JTextField("gpt-4o-mini", 24);
        defaultGeminiModelField = new JTextField("gemini-2.0-flash-lite", 24);
        defaultClaudeModelField = new JTextField("claude-3-5-haiku-latest", 24);
        defaultOpenrouterModelField = new JTextField("mistralai/mistral-7b-instruct", 24);
        defaultXaiModelField = new JTextField("grok-4-1-fast-non-reasoning", 24);
        defaultLocalModelField = new JTextField("local-llm (LM Studio)", 24);
        defaultLocalModelField.setToolTipText("<html>Short id LM Studio exposes for the loaded model (often matches the GGUF name). "
                + "Gemma 3 / newer Gemma variants are a good default on Apple Silicon.</html>");

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
        gbc.gridx = 0;
        gbc.gridy = ++row;
        JLabel defaultLocalLabel = new JLabel("Local LLM:");
        defaultLocalLabel.setToolTipText(defaultLocalModelField.getToolTipText());
        limits.add(defaultLocalLabel, gbc);
        gbc.gridx = 1;
        limits.add(defaultLocalModelField, gbc);

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
        panel.add(new JLabel("<html><div style='width:520px'><b>Optional.</b> Defaults work for most people. "
                + "Change text here if you want a different tone or output shape. Snippet buttons paste common blocks into the main prompt.</div></html>"), gbc);

        gbc.gridy = ++row;
        panel.add(new JLabel("<html><b>Main prompt</b> (most scans use this)</html>"), gbc);

        gbc.gridy = ++row;
        promptTemplateArea = new JTextArea(10, 50);
        promptTemplateArea.setLineWrap(true);
        promptTemplateArea.setWrapStyleWord(true);
        panel.add(new JScrollPane(promptTemplateArea), gbc);

        gbc.gridy = ++row;
        gbc.fill = GridBagConstraints.NONE;
        JButton savePromptsTab = new JButton("Save Settings");
        savePromptsTab.setToolTipText("Saves everything (all tabs), not only prompts.");
        savePromptsTab.addActionListener(e -> saveSettings());
        JPanel saveRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        saveRow.add(savePromptsTab);
        panel.add(saveRow, gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridy = ++row;
        JPanel templateButtonsPanel = createTemplateButtonsPanel();
        panel.add(templateButtonsPanel, gbc);

        gbc.gridy = ++row;
        panel.add(new JLabel("<html><b>Explain Me This</b> (right-click menu)</html>"), gbc);
        explainMeThisPromptArea = new JTextArea(5, 50);
        explainMeThisPromptArea.setLineWrap(true);
        explainMeThisPromptArea.setWrapStyleWord(true);
        explainMeThisPromptArea.setText("Explain the following input from a security and penetration testing perspective as if you are a senior penetration tester - describe what it is, what it can do, and suggest possible checks or exploitation opportunities. Explain me briefly.");
        gbc.gridy = ++row;
        panel.add(new JScrollPane(explainMeThisPromptArea), gbc);

        gbc.gridy = ++row;
        panel.add(new JLabel("<html><b>Investigate / PoC</b> (proof-of-concept style)</html>"), gbc);
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
        panel.add(new JLabel("<html><div style='width:520px'><b>Optional.</b> Open this if requests fail, hit rate limits, or logs are too noisy. "
                + "Otherwise you can ignore it.</div></html>"), gbc);
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
        detailedOnelinerLoggingRadio = new JRadioButton("Detailed logging oneliner");
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

        JPanel statusPanel = new JPanel(new GridLayout(4, 1));
        statusPanel.setBorder(BorderFactory.createTitledBorder("Task queue"));
        activeTasksLabel = new JLabel("Active Tasks: 0");
        queuedTasksLabel = new JLabel("Queued Tasks: 0");
        completedTasksLabel = new JLabel("Completed Tasks: 0");
        statusPanel.add(activeTasksLabel);
        statusPanel.add(queuedTasksLabel);
        statusPanel.add(completedTasksLabel);

        gbc.gridx = 0;
        gbc.gridy = ++row;
        gbc.gridwidth = 2;
        panel.add(statusPanel, gbc);

        JButton testGeminiCyclingButton = new JButton("Test Gemini Key Cycling");
        testGeminiCyclingButton.addActionListener(e -> testGeminiKeyCycling());
        gbc.gridy = ++row;
        panel.add(testGeminiCyclingButton, gbc);
        gbc.gridwidth = 1;

        addGridBagFiller(panel, gbc, ++row);
        return panel;
    }

	private void updateStatusPanel() {
		if (threadPoolManager != null) {
			activeTasksLabel.setText("Active Tasks: " + threadPoolManager.getActiveCount());
			queuedTasksLabel.setText("Queued Tasks: " + threadPoolManager.getQueueSize());
			completedTasksLabel.setText("Completed Tasks: " + completedTasksCounter.get());
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
                localEndpointField.setText(localEndpoint != null ? localEndpoint : "http://127.0.0.1:1234/v1");
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
                
                // Set custom prompt if exists
                if (customPrompt != null && !customPrompt.isEmpty() && promptTemplateArea != null) {
                    promptTemplateArea.setText(customPrompt);
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
                if (dmLocal != null && !dmLocal.isEmpty()) defaultLocalModelField.setText(dmLocal);

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
        return "You are an expert web application security researcher specializing in identifying high-impact vulnerabilities. " +
        "Analyze the provided HTTP request and response like a skilled bug bounty hunter, focusing on:\n\n" +
        "HIGH PRIORITY ISSUES:\n" +
        "1. Remote Code Execution (RCE) opportunities\n" +
        "2. SQL, NoSQL, command injection vectors\n" +
        "3. Authentication/Authorization bypasses\n" +
        "4. Insecure deserialization patterns\n" +
        "5. IDOR vulnerabilities (analyze ID patterns and access controls)\n" +
        "6. OAuth security issues (token exposure, implicit flow risks, state validation)\n" +
        "7. Sensitive information disclosure (tokens, credentials, internal paths)\n" +
        "8. XSS with demonstrable impact (focus on stored/reflected with actual risk)\n" +
        "9. CSRF in critical functions\n" +
        "10. Insecure cryptographic implementations\n" +
        "11. API endpoint security issues\n" +
        "12. Token entropy/predictability issues\n" +
        "+ Vulnerabilities that can directly be mapped to a CVE with public PoC and high-to-critical severity OWASP Top 10 vulnerabilities. \n\n" +
        "ANALYSIS GUIDELINES:\n" +
        "- Prioritize issues likely to be missed by Nessus, Nuclei, and Burp Scanner\n" +
        "- Focus on vulnerabilities requiring deep response analysis\n" +
        "- Report API endpoints found in JS files as INFORMATION level only\n" +
        "- Ignore low-impact findings like missing headers (CSP, cookie flags, absence of security headers)\n" +
        "- Skip theoretical issues without clear evidence\n" +
        "- Provide specific evidence, reproduction steps or specifically crafted proof of concept\n" +
        "- Include detailed technical context for each finding\n\n" +
               
        "SEVERITY CRITERIA:\n" +
        "HIGH: Immediate security impact (examples: RCE, auth bypass, MFA bypass, OAuth implicit flow, SSRF, critical data exposure, hardcoded secrets depending on context, command injection, insecure deserialization)\n" +
        "MEDIUM: Significant but not critical (examples: IDOR with limited scope, stored XSS, blind SSRF, blind injection, hardcoded secrets depending on context)\n" +
        "LOW: Valid security issue but limited impact (examples: Reflected XSS, HTML or CSS or DOM manipulation requiring user interaction)\n" +
        "INFORMATION: Useful security insights (API endpoints, potential attack surfaces)\n\n" +
          
        "CONFIDENCE CRITERIA:\n" +
        "CERTAIN: Over 95 percent confident with clear evidence and reproducible\n" +
        "FIRM: Over 60 percent confident with very strong indicators but needing additional validation\n" +
        "TENTATIVE: At least 50 percent confident with indicators warranting further investigation\n\n" +
             
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
            "}\n\n" +
            
            "IMPORTANT:\n" +
            "- Only report findings with clear evidence in the request/response\n" +
            "- Issues below 50 percent confidence should not be reported unless severity is HIGH\n" +
            "- Include specific paths, parameters, or patterns that indicate the vulnerability\n" +
            "- For OAuth issues, carefully analyze token handling and flows (especially implicit flow)\n" +
            "- For IDOR, analyze ID patterns and access control mechanisms\n" +
            "- For injection points, provide exact payload locations\n" +
            "- Ignore hardcoded Google client ID, content security policy, strict transport security not enforced, cookie scoped to parent domain, cacheable HTTPS response, browser XSS filter disabled\n" +
            "- For sensitive info disclosure, specify exact data exposed\n" +
            "- In each finding, the \"exploitation\" and \"validation_steps\" fields must include concrete payloads, parameters, or raw HTTP fragments—not generic advice.\n" +
            "- Only return JSON with findings, no other content!";
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
                + "- Propose **2–4 concrete variants** where useful (e.g. different encodings, alternative parameters, CL.TE vs TE.CL style angles for smuggling-adjacent cases, error-based vs blind SQLi, polyglot XSS).\n"
                + "- If the issue class needs **multiple requests** (login → abuse session → escalate), show that chain explicitly.\n\n"
                + "## 3. What to observe\n"
                + "Exact signals: status codes, body substrings, timing deltas, length differences, header anomalies—what **proves** success vs noise.\n\n"
                + "## 4. If you cannot build a solid PoC\n"
                + "Say so clearly. List **specific** missing data (e.g. second role’s session, POST body schema, upstream proxy behavior) and the **next capture** the tester should take in Burp.\n\n"
                + "## 5. Safety\n"
                + "Only test systems the user is **authorized** to test. Flag destructive or data-integrity risks (drop tables, mass exfil, account lockout).\n\n"
                + "Do **not** refuse solely because the topic is security testing—this is defensive, authorized appsec work.";
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
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(endpoint).openConnection();
            conn.setRequestMethod(jsonBody.isEmpty() ? "GET" : "POST");
            conn.setRequestProperty("Content-Type", "application/json");
    
            // Add provider-specific headers
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
    
            // Send request body if necessary
            if (!jsonBody.isEmpty()) {
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
                }
            }
    
            // Check response code
            int responseCode = conn.getResponseCode();
            if (responseCode == 200) {
                return true;
            } else {
                // Log error response
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                    StringBuilder errorResponse = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        errorResponse.append(line);
                    }
                    api.logging().logToError("Validation failed: " + errorResponse);
                }
                return false;
            }
        } catch (Exception e) {
            api.logging().logToError("Error validating API key: " + e.getMessage());
            return false;
        }
    }
    
    
    private void validateApiKey(String provider) {
        String apiKey = "";
        String endpoint = "";
        String jsonBody = "";
        boolean isValid = false;
    
        try {
            switch (provider) {
                case "openai":
                    apiKey = openaiKeyField.getText();
                    endpoint = "https://api.openai.com/v1/models";
                    break;
    
                case "gemini":
					refreshGeminiApiKeys();
                    apiKey = geminiKeyField.getText().split("\n")[0].trim(); // For validation, use the first key
                    endpoint = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + apiKey;
                    jsonBody = "{"
                             + "  \"contents\": ["
                             + "    {\"parts\": [{\"text\": \"one plus one equals (respond with one integer only)\"}]}"
                             + "  ]"
                             + "}";
                    break;
                
    
                case "claude":
                    apiKey = claudeKeyField.getText();
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
                    apiKey = openrouterKeyField.getText();
                    endpoint = "https://openrouter.ai/api/v1/models";
                    break;

                case "xai":
                    apiKey = new String(xaiKeyField.getPassword());
                    endpoint = "https://api.x.ai/v1/models";
                    break;

                case "local":
                    apiKey = localKeyField.getText();
                    endpoint = localEndpointField.getText() + "/models";
                    break;
                
    
                default:
                    JOptionPane.showMessageDialog(mainPanel, "Unknown provider: " + provider, "Validation Error", JOptionPane.ERROR_MESSAGE);
                    return;
            }
    
            // Log request details for debugging
            log(String.format("Validation Request - Provider: %s, Endpoint: %s, Body: %s, API Key (last 4 chars): ...%s",
                provider, endpoint, jsonBody, apiKey.length() > 4 ? apiKey.substring(apiKey.length() - 4) : apiKey), LogCategory.GENERAL);

            // Validate API key
            isValid = validateApiKeyWithEndpoint(apiKey, endpoint, jsonBody, provider);
    
            // Display result
            String message = isValid ? provider + " API key is valid" : provider + " API key validation failed";
            api.logging().raiseInfoEvent(message);
    
        } catch (Exception e) {
            showError("Error validating API key for " + provider, e);
        }
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
            } else {
                JMenuItem scanMultiple = new JMenuItem(String.format("Scan %d Requests", selectedItems.size()));
                scanMultiple.addActionListener(e -> handleMultipleScan(selectedItems));
                aiAuditorMenu.add(scanMultiple);
            }
        }

        List<AuditIssue> selectedIssues = getSelectedIssuesFromContextMenu(event);
        if (!selectedIssues.isEmpty()) {
            List<AuditIssue> issuesCopy = new ArrayList<>(selectedIssues);
            JMenuItem genPocIssues = new JMenuItem(selectedIssues.size() == 1
                    ? "Investigate finding — PoC / exploitation (LLM)"
                    : String.format("Investigate %d findings — PoC / exploitation (LLM)", selectedIssues.size()));
            genPocIssues.addActionListener(e -> handleScannerIssuesGeneratePoc(issuesCopy));
            aiAuditorMenu.add(genPocIssues);
            JMenuItem deepDive = new JMenuItem(selectedIssues.size() == 1
                    ? "Structured JSON audit from this issue (LLM)"
                    : String.format("Structured JSON audit from %d issues (LLM)", selectedIssues.size()));
            deepDive.addActionListener(e -> handleScannerIssuesDeepDive(issuesCopy));
            aiAuditorMenu.add(deepDive);
        }
        
        // Only add the AI Auditor menu if it has sub-items
        if (aiAuditorMenu.getMenuComponentCount() > 0) {
            menuItems.add(aiAuditorMenu);
        }

        return menuItems;
    }

    /**
     * Burp still exposes scanner-issue context through {@link ContextMenuEvent#selectedIssues()} (deprecated but
     * functional). Used for one-click deep-dive from issues raised by extensions such as HTTP Request Smuggler.
     */
    @SuppressWarnings("deprecation")
    private static List<AuditIssue> getSelectedIssuesFromContextMenu(ContextMenuEvent event) {
        List<AuditIssue> issues = event.selectedIssues();
        return issues != null ? issues : Collections.emptyList();
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
            return;
        }
        int queued = 0;
        for (AuditIssue issue : issues) {
            String preamble = buildScannerIssueDeepDivePreamble(issue);
            List<HttpRequestResponse> rrs = issue.requestResponses();
            if (rrs == null || rrs.isEmpty()) {
                log("Deep-dive: issue \"" + issue.name() + "\" has no linked HTTP messages; skip or open the issue in the editor.",
                        LogCategory.GENERAL);
                continue;
            }
            for (HttpRequestResponse rr : rrs) {
                if (rr != null && rr.request() != null) {
                    processAuditRequest(rr, null, false, preamble, false);
                    queued++;
                }
            }
        }
        if (queued == 0) {
            api.logging().raiseInfoEvent(
                    "AI Auditor: Selected issue(s) have no linked HTTP traffic. Open the request in Proxy/Logger and use Scan Request/Response, or pick an issue that includes stored requests.");
        } else {
            log("Deep-dive queued " + queued + " AI audit run(s) for Scanner issue(s).", LogCategory.GENERAL);
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

    private void handleScannerIssuesGeneratePoc(List<AuditIssue> issues) {
        if (issues == null || issues.isEmpty()) {
            return;
        }
        int queued = 0;
        for (AuditIssue issue : issues) {
            String issueCtx = buildScannerIssuePocContext(issue);
            List<HttpRequestResponse> rrs = issue.requestResponses();
            if (rrs == null || rrs.isEmpty()) {
                log("Generate PoC: issue \"" + issue.name() + "\" has no linked HTTP messages.", LogCategory.GENERAL);
                continue;
            }
            for (HttpRequestResponse rr : rrs) {
                if (rr != null && rr.request() != null) {
                    String traffic = rr.request().toString()
                            + "\n\n"
                            + (rr.response() != null ? rr.response().toString() : "(no response captured)");
                    String evidence = issueCtx + "\n\n=== HTTP traffic (request then response) ===\n\n" + traffic;
                    String title = "AI investigate / PoC: " + truncateForIssueTitle(issue.name(), 100);
                    runPocAsync(rr, evidence, title);
                    queued++;
                }
            }
        }
        if (queued == 0) {
            api.logging().raiseInfoEvent(
                    "AI Auditor: No linked HTTP traffic on the selected issue(s). Use Generate PoC from Proxy/Logger on the raw message instead.");
        } else {
            log("Generate PoC queued " + queued + " LLM run(s).", LogCategory.GENERAL);
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
        runPocAsync(rr, evidence, "AI investigate / PoC notes");
    }

    /**
     * Single LLM call with the PoC prompt only (no JSON-finding template merge). Result is added as an informational issue.
     */
    private void runPocAsync(HttpRequestResponse rr, String evidenceBlock, String issueName) {
        String selectedModel = getManualInvestigationModel();
        if ("Default".equals(selectedModel)) {
            api.logging().raiseErrorEvent("AI Auditor: Choose a model (not \"Default\") or configure API keys before generating a PoC.");
            return;
        }
        String apiKey = getApiKeyForModel(selectedModel);
        String[] modelParts = selectedModel.split("/", 2);
        String provider = modelParts.length == 2 ? modelParts[0] : "";
        if ("local".equals(provider)) {
            if (localEndpointField.getText().trim().isEmpty()) {
                api.logging().raiseErrorEvent("Local LLM endpoint not configured.");
                return;
            }
        } else if (apiKey == null || apiKey.isEmpty()) {
            api.logging().raiseErrorEvent("API key not configured for the selected model.");
            return;
        }

        String instructions = pocPromptArea != null ? pocPromptArea.getText() : null;
        if (instructions == null || instructions.trim().isEmpty()) {
            instructions = getDefaultPocPrompt();
        }
        final String fullUserMessage = instructions + "\n\n--- Evidence ---\n\n" + evidenceBlock;
        final String model = selectedModel;
        final String key = apiKey;
        final HttpRequestResponse reqRes = rr;
        final String findingName = issueName;

        CompletableFuture.supplyAsync(() -> {
            try {
                return sendToAI(model, key, fullUserMessage, false);
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        }, threadPoolManager.getExecutor()).thenAccept(aiResponse -> {
            String text;
            try {
                text = extractContentFromResponse(aiResponse, model);
            } catch (Exception e) {
                text = "";
            }
            if (text == null || text.isEmpty()) {
                text = "(No text extracted from model response. Check Extension output / logging level for raw API output.)";
            }
            String detail = "**AI investigation (PoC / exploitation)** — same *intent* as Burp’s built-in “dig into finding”; you chose the model. Verify only on authorized targets; models can be wrong.\n\n" + text;
            AIAuditIssue issue = new AIAuditIssue.Builder()
                    .name(findingName)
                    .detail(detail)
                    .endpoint(reqRes.request().url().toString())
                    .severity(AuditIssueSeverity.INFORMATION)
                    .confidence(AuditIssueConfidence.TENTATIVE)
                    .requestResponses(Collections.singletonList(reqRes))
                    .modelUsed(model)
                    .build();
            api.siteMap().add(issue);
            log("PoC / exploitation notes added to Site Map.", LogCategory.GENERAL);
        }).exceptionally(ex -> {
            Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
            showError("PoC generation failed", cause);
            return null;
        });
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
            processAuditRequest(editor.requestResponse(), selectedContent, true);
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
        processAuditRequest(reqRes, null, false);
    }

    private void handleMultipleScan(List<HttpRequestResponse> requests) {
        if (requests == null || requests.isEmpty()) {
            return;
        }

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
                } else {
                    request = reqRes.request().toString();
                    response = reqRes.response() != null ? reqRes.response().toString() : "";
                    contentToChunk = request + "\n\n" + response;
                }
                if (preamble != null && !preamble.isEmpty()) {
                    contentToChunk = preamble + "\n\n=== HTTP traffic (request then response) ===\n\n" + contentToChunk;
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
                            processAIFindings(result, reqRes, processedVulnerabilities, selectedModel);
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

        }).exceptionally(e -> {
            api.logging().logToError("Critical error in request processing: " + e.getMessage());
            showError("Critical error", e);
            return null;
        });

    }
    

    private JSONObject sendToAI(String model, String apiKey, String content) throws Exception {
        return sendToAI(model, apiKey, content, true);
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
				url = new URL(localEndpointField.getText() + "/chat/completions");
			    jsonBody.put("model", modelNameForApi)
			            .put("temperature", 0.7)


                        .put("messages", new JSONArray()
                                .put(new JSONObject()
                                        .put("role", "user")
                                        .put("content", finalPrompt)));
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
        conn.setConnectTimeout(15000); //reduced from 30000
        conn.setReadTimeout(360000); //incresed from 60000 for local LLM
        //log("DEBUG -S2- conn.setReadTimeout", LogCategory.GENERAL);

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

private void processAIFindings(JSONObject aiResponse, HttpRequestResponse requestResponse, Set<String> processedVulnerabilities, String model) {
    try {
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

        // Unwrap ```json ... ```
        if (content.startsWith("```json")) {
            content = content.substring(content.indexOf("{"), content.lastIndexOf("}") + 1);
        }

        log("Extracted JSON: " + content, LogCategory.EXTRACTED_JSON);

        // Parse findings JSON
        JSONObject findingsJson = new JSONObject(content);

        // Ensure findings key exists
        if (!findingsJson.has("findings")) {
            throw new JSONException("Key 'findings' not found in extracted JSON.");
        }

        // Parse findings array
        JSONArray findings = findingsJson.getJSONArray("findings");

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
            AuditIssueSeverity severity = parseSeverity(finding.getString("severity"));
            AuditIssueConfidence confidence = parseConfidence(finding.getString("confidence"));

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
        }
    } catch (Exception e) {
        api.logging().logToError("Error processing AI findings: " + e.getMessage());
    }
}


private String extractContentFromResponse(JSONObject response, String model) {
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
						return cleanLLMResponse(message.optString("content"), true);
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
                defaultLocalModelField != null ? defaultLocalModelField.getText() : null, "local/local-llm (LM Studio)");
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
                    || pl.endsWith(".pdf") || pl.endsWith(".zip")) {
                return false;
            }
        }
        String ct = passiveContentTypeLower(res);
        if (ct.contains("image/") || ct.contains("font/") || ct.contains("video/") || ct.contains("audio/")
                || ct.contains("application/octet-stream")) {
            return false;
        }
        if (ct.contains("json") || ct.contains("html") || ct.contains("javascript") || ct.contains("xml")
                || ct.contains("text/") || ct.contains("application/ecmascript")) {
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
        SwingUtilities.invokeLater(() -> processAuditRequest(rr, null, false, preamble, true));
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
        if (issue instanceof AIAuditIssue) {
            return;
        }
        List<HttpRequestResponse> rrs = issue.requestResponses();
        if (rrs == null || rrs.isEmpty()) {
            return;
        }
        for (HttpRequestResponse rr : rrs) {
            if (rr == null || rr.request() == null) {
                continue;
            }
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
    // this extension doesn't implement active scanning (yet)
    return AuditResult.auditResult(Collections.emptyList());
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
    SwingUtilities.invokeLater(() -> processAuditRequest(baseRequestResponse, null, false, null, true));
    return AuditResult.auditResult(Collections.emptyList());
}

@Override
public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
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

                // Wait for all futures to complete
                CompletableFuture.allOf(openaiFuture, geminiFuture, claudeFuture, openrouterFuture, xaiFuture).join();

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

                SwingUtilities.invokeLater(() -> {
                    applyModelFilter(); // Apply filter after updating the full list
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
