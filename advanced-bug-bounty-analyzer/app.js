// BugHunter Pro - Advanced Bug Bounty Platform
class BugHunterPro {
    constructor() {
        this.currentTarget = null;
        this.vulnerabilities = [];
        this.reconData = {};
        this.analysisResults = {};
        this.currentNotes = '';
        this.methodologyProgress = {};
        
        // Vulnerability data from the provided JSON
        this.vulnerabilityTypes = [
            {
                id: "sql_injection",
                name: "SQL Injection",
                category: "Injection",
                owasp: "A03:2021",
                severity: "High",
                description: "Improper neutralization of special elements used in SQL commands",
                impact: "Data breach, unauthorized data access, data manipulation",
                remediation: "Use parameterized queries, input validation, least privilege access"
            },
            {
                id: "xss",
                name: "Cross-Site Scripting (XSS)",
                category: "Injection",
                owasp: "A03:2021", 
                severity: "Medium",
                description: "Improper neutralization of input during web page generation",
                impact: "Session hijacking, defacement, malicious code execution",
                remediation: "Input validation, output encoding, Content Security Policy"
            },
            {
                id: "broken_access_control",
                name: "Broken Access Control",
                category: "Authorization",
                owasp: "A01:2021",
                severity: "High",
                description: "Restrictions on authenticated users not properly enforced",
                impact: "Unauthorized access to data or functionality",
                remediation: "Implement proper access controls, deny by default, server-side validation"
            },
            {
                id: "crypto_failures",
                name: "Cryptographic Failures",
                category: "Cryptography",
                owasp: "A02:2021",
                severity: "High",
                description: "Weak encryption, exposed sensitive data",
                impact: "Data exposure, man-in-the-middle attacks",
                remediation: "Use strong encryption, secure key management, HTTPS enforcement"
            },
            {
                id: "insecure_design",
                name: "Insecure Design",
                category: "Design",
                owasp: "A04:2021",
                severity: "Medium",
                description: "Missing or ineffective control design",
                impact: "Various security control bypasses",
                remediation: "Secure development lifecycle, threat modeling, security architecture"
            },
            {
                id: "security_misconfig",
                name: "Security Misconfiguration",
                category: "Configuration",
                owasp: "A05:2021",
                severity: "Medium",
                description: "Missing security hardening, default configurations",
                impact: "Unauthorized access, information disclosure",
                remediation: "Security hardening, regular updates, proper configuration management"
            },
            {
                id: "outdated_components",
                name: "Vulnerable Components",
                category: "Components", 
                owasp: "A06:2021",
                severity: "High",
                description: "Using components with known vulnerabilities",
                impact: "Full system compromise, data breach",
                remediation: "Regular updates, vulnerability scanning, component inventory"
            },
            {
                id: "auth_failures",
                name: "Authentication Failures",
                category: "Authentication",
                owasp: "A07:2021",
                severity: "High", 
                description: "Broken authentication mechanisms",
                impact: "Account takeover, identity theft",
                remediation: "Multi-factor authentication, strong password policies, session management"
            },
            {
                id: "integrity_failures",
                name: "Software Integrity Failures",
                category: "Integrity",
                owasp: "A08:2021",
                severity: "Medium",
                description: "Code or infrastructure integrity compromised",
                impact: "Malicious code execution, supply chain attacks",
                remediation: "Code signing, integrity checks, secure CI/CD pipelines"
            },
            {
                id: "ssrf",
                name: "Server-Side Request Forgery",
                category: "Server-Side",
                owasp: "A10:2021",
                severity: "High",
                description: "Server fetches remote resource without validating URL",
                impact: "Internal network access, data exfiltration",
                remediation: "URL validation, network segmentation, allow-listing"
            }
        ];

        this.methodology = [
            {
                phase: "1. Reconnaissance",
                description: "Information gathering and target analysis",
                steps: [
                    "Subdomain enumeration",
                    "Port scanning", 
                    "Technology stack identification",
                    "Asset discovery",
                    "DNS enumeration"
                ]
            },
            {
                phase: "2. Vulnerability Analysis",
                description: "Systematic vulnerability identification",
                steps: [
                    "OWASP Top 10 testing",
                    "Input validation testing",
                    "Authentication testing",
                    "Session management testing",
                    "Business logic testing"
                ]
            },
            {
                phase: "3. Exploitation",
                description: "Proof of concept development",
                steps: [
                    "Vulnerability verification",
                    "Impact assessment",
                    "Exploit development",
                    "Evidence collection",
                    "Documentation"
                ]
            },
            {
                phase: "4. Reporting",
                description: "Comprehensive vulnerability reporting",
                steps: [
                    "Severity assessment",
                    "Technical description",
                    "Impact analysis",
                    "Remediation recommendations",
                    "Executive summary"
                ]
            }
        ];

        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeMethodology();
        this.updateDashboardStats();
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });

        // Target setup
        document.getElementById('startAnalysis').addEventListener('click', () => this.startAnalysis());

        // Reconnaissance
        document.getElementById('startRecon').addEventListener('click', () => this.startReconnaissance());

        // Vulnerability scanner
        document.getElementById('startVulnScan').addEventListener('click', () => this.startVulnerabilityScanning());

        // Deep analysis
        document.getElementById('startDeepAnalysis').addEventListener('click', () => this.startDeepAnalysis());

        // Reports
        document.getElementById('generateReport').addEventListener('click', () => this.generateReport());
        document.getElementById('exportFindings').addEventListener('click', () => this.exportFindings());

        // Notes
        document.getElementById('saveNotes').addEventListener('click', () => this.saveNotes());

        // Modal
        document.getElementById('closeVulnModal').addEventListener('click', () => this.closeModal());
    }

    switchTab(tabName) {
        // Update nav buttons
        document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        document.getElementById(tabName).classList.add('active');
    }

    async startAnalysis() {
        const targetUrl = document.getElementById('targetUrl').value.trim();
        const scopeDefinition = document.getElementById('scopeDefinition').value.trim();

        if (!targetUrl) {
            alert('Please enter a target URL');
            return;
        }

        if (!this.isValidUrl(targetUrl)) {
            alert('Please enter a valid URL');
            return;
        }

        this.currentTarget = {
            url: targetUrl,
            domain: this.extractDomain(targetUrl),
            scope: scopeDefinition.split('\n').filter(line => line.trim())
        };

        await this.analyzeTarget();
        this.updateDashboardStats();
    }

    isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    extractDomain(url) {
        try {
            return new URL(url).hostname;
        } catch (_) {
            return url;
        }
    }

    async analyzeTarget() {
        const targetInfoEl = document.getElementById('targetInfo');
        targetInfoEl.innerHTML = `
            <div class="target-details">
                <div class="detail-item">
                    <span class="detail-label">Domain</span>
                    <span class="detail-value">${this.currentTarget.domain}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">URL</span>
                    <span class="detail-value">${this.currentTarget.url}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Status</span>
                    <span class="detail-value status--success">Active</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">Scope Items</span>
                    <span class="detail-value">${this.currentTarget.scope.length} rules</span>
                </div>
            </div>
        `;
    }

    async startReconnaissance() {
        if (!this.currentTarget) {
            alert('Please set a target first');
            return;
        }

        await this.runSubdomainEnumeration();
        await this.runPortScanning();
        await this.runTechnologyDetection();
        await this.runDnsInformation();
    }

    async runSubdomainEnumeration() {
        const spinner = document.getElementById('subdomainSpinner');
        const resultsEl = document.getElementById('subdomainResults');
        
        spinner.classList.remove('hidden');
        resultsEl.innerHTML = '<div class="no-results">Enumerating subdomains...</div>';

        // Simulate subdomain enumeration
        await this.delay(2000);

        const subdomains = this.generateSubdomains(this.currentTarget.domain);
        this.reconData.subdomains = subdomains;

        spinner.classList.add('hidden');
        resultsEl.innerHTML = subdomains.map(sub => `
            <div class="subdomain-item">
                <span class="subdomain-name">${sub.name}</span>
                <span class="subdomain-status">${sub.status}</span>
            </div>
        `).join('');
    }

    generateSubdomains(domain) {
        const prefixes = ['www', 'api', 'admin', 'blog', 'shop', 'dev', 'staging', 'mail', 'cdn', 'assets'];
        return prefixes.map(prefix => ({
            name: `${prefix}.${domain}`,
            status: Math.random() > 0.3 ? 'Active' : 'Inactive'
        }));
    }

    async runPortScanning() {
        const spinner = document.getElementById('portSpinner');
        const resultsEl = document.getElementById('portResults');
        
        spinner.classList.remove('hidden');
        resultsEl.innerHTML = '<div class="no-results">Scanning ports...</div>';

        await this.delay(3000);

        const ports = this.generatePortScan();
        this.reconData.ports = ports;

        spinner.classList.add('hidden');
        resultsEl.innerHTML = ports.map(port => `
            <div class="port-item">
                <span class="port-number">${port.number}/${port.protocol}</span>
                <span class="port-status">${port.service}</span>
            </div>
        `).join('');
    }

    generatePortScan() {
        const commonPorts = [
            { number: 80, protocol: 'tcp', service: 'HTTP' },
            { number: 443, protocol: 'tcp', service: 'HTTPS' },
            { number: 22, protocol: 'tcp', service: 'SSH' },
            { number: 25, protocol: 'tcp', service: 'SMTP' },
            { number: 53, protocol: 'tcp', service: 'DNS' },
            { number: 8080, protocol: 'tcp', service: 'HTTP-Alt' },
            { number: 3306, protocol: 'tcp', service: 'MySQL' }
        ];
        return commonPorts.filter(() => Math.random() > 0.4);
    }

    async runTechnologyDetection() {
        await this.delay(1500);
        
        const technologies = ['Apache 2.4.41', 'PHP 7.4', 'MySQL 8.0', 'WordPress 5.8', 'jQuery 3.6.0', 'Bootstrap 4.5'];
        this.reconData.technologies = technologies;

        document.getElementById('techStack').innerHTML = 
            technologies.map(tech => `<span class="tech-item">${tech}</span>`).join('');
    }

    async runDnsInformation() {
        await this.delay(1000);

        const dnsRecords = [
            { type: 'A', value: '192.168.1.100' },
            { type: 'MX', value: 'mail.example.com' },
            { type: 'NS', value: 'ns1.example.com' },
            { type: 'TXT', value: 'v=spf1 include:_spf.google.com' }
        ];

        this.reconData.dns = dnsRecords;

        document.getElementById('dnsInfo').innerHTML = dnsRecords.map(record => `
            <div class="dns-record">
                <span class="dns-type">${record.type}</span>
                <span class="dns-value">${record.value}</span>
            </div>
        `).join('');
    }

    async startVulnerabilityScanning() {
        if (!this.currentTarget) {
            alert('Please set a target first');
            return;
        }

        const scanType = document.getElementById('scanType').value;
        const progressEl = document.getElementById('scanProgress');
        const progressBar = document.getElementById('scanProgressBar');
        const progressText = document.getElementById('scanProgressText');
        const statusEl = document.getElementById('scanStatus');
        const gridEl = document.getElementById('vulnerabilitiesGrid');

        progressEl.classList.remove('hidden');
        gridEl.innerHTML = '';

        const scanSteps = [
            'Initializing scan engines...',
            'Testing for SQL injection vulnerabilities...',
            'Checking for XSS vulnerabilities...',
            'Analyzing authentication mechanisms...',
            'Testing access controls...',
            'Scanning for cryptographic issues...',
            'Checking for security misconfigurations...',
            'Testing for SSRF vulnerabilities...',
            'Analyzing session management...',
            'Finalizing scan results...'
        ];

        for (let i = 0; i < scanSteps.length; i++) {
            const progress = ((i + 1) / scanSteps.length) * 100;
            progressBar.style.width = `${progress}%`;
            progressText.textContent = `${Math.round(progress)}%`;
            statusEl.textContent = scanSteps[i];
            
            await this.delay(800);
        }

        // Generate vulnerabilities based on scan type
        this.vulnerabilities = this.generateVulnerabilities(scanType);
        
        progressEl.classList.add('hidden');
        this.displayVulnerabilities();
        this.updateDashboardStats();
    }

    generateVulnerabilities(scanType) {
        let vulnCount = scanType === 'full' ? 5 : scanType === 'quick' ? 2 : 3;
        const vulnerabilities = [];

        for (let i = 0; i < vulnCount; i++) {
            const baseVuln = this.vulnerabilityTypes[Math.floor(Math.random() * this.vulnerabilityTypes.length)];
            const vuln = {
                ...baseVuln,
                id: `${baseVuln.id}_${Date.now()}_${i}`,
                location: this.generateVulnLocation(),
                evidence: this.generateEvidence(baseVuln),
                cvss: this.generateCVSS(baseVuln.severity),
                discovered: new Date().toISOString()
            };
            vulnerabilities.push(vuln);
        }

        return vulnerabilities;
    }

    generateVulnLocation() {
        const locations = [
            `/login.php?user=admin`,
            `/search?q=test`,
            `/api/users/profile`,
            `/admin/dashboard`,
            `/contact.php`,
            `/products?id=123`,
            `/upload.php`,
            `/forgot-password.php`
        ];
        return locations[Math.floor(Math.random() * locations.length)];
    }

    generateEvidence(vuln) {
        const evidenceTemplates = {
            sql_injection: "Payload: ' OR '1'='1 -- Response: MySQL error revealing database structure",
            xss: "Payload: <script>alert('XSS')</script> Successfully executed in browser",
            broken_access_control: "Direct access to /admin/users without authentication returned sensitive data",
            crypto_failures: "SSL/TLS configuration allows weak ciphers (RC4, MD5)",
            ssrf: "Internal network scan via http://localhost:8080/admin returned internal services"
        };
        return evidenceTemplates[vuln.id] || "Evidence collected during automated scanning";
    }

    generateCVSS(severity) {
        const cvssMap = {
            'Critical': (Math.random() * 1.5 + 8.5).toFixed(1),
            'High': (Math.random() * 2 + 7).toFixed(1),
            'Medium': (Math.random() * 3 + 4).toFixed(1),
            'Low': (Math.random() * 3 + 1).toFixed(1)
        };
        return cvssMap[severity] || '5.0';
    }

    displayVulnerabilities() {
        const gridEl = document.getElementById('vulnerabilitiesGrid');
        
        if (this.vulnerabilities.length === 0) {
            gridEl.innerHTML = '<div class="no-results">No vulnerabilities found</div>';
            return;
        }

        gridEl.innerHTML = this.vulnerabilities.map(vuln => `
            <div class="vulnerability-card ${vuln.severity.toLowerCase()}" onclick="app.showVulnerabilityDetails('${vuln.id}')">
                <div class="vuln-header">
                    <h4 class="vuln-title">${vuln.name}</h4>
                    <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                </div>
                <div class="vuln-category">${vuln.category} • ${vuln.owasp}</div>
                <div class="vuln-description">${vuln.description}</div>
                <div class="owasp-tag">CVSS: ${vuln.cvss}</div>
            </div>
        `).join('');
    }

    showVulnerabilityDetails(vulnId) {
        const vuln = this.vulnerabilities.find(v => v.id === vulnId);
        if (!vuln) return;

        const modal = document.getElementById('vulnModal');
        const title = document.getElementById('vulnModalTitle');
        const body = document.getElementById('vulnModalBody');

        title.textContent = vuln.name;
        body.innerHTML = `
            <div class="vuln-detail-section">
                <h4>Overview</h4>
                <p><strong>Category:</strong> ${vuln.category}</p>
                <p><strong>OWASP Classification:</strong> ${vuln.owasp}</p>
                <p><strong>Severity:</strong> ${vuln.severity} (CVSS: ${vuln.cvss})</p>
                <p><strong>Location:</strong> ${vuln.location}</p>
            </div>
            
            <div class="vuln-detail-section">
                <h4>Description</h4>
                <p>${vuln.description}</p>
            </div>
            
            <div class="vuln-detail-section">
                <h4>Impact</h4>
                <p>${vuln.impact}</p>
            </div>
            
            <div class="vuln-detail-section">
                <h4>Evidence</h4>
                <p>${vuln.evidence}</p>
            </div>
            
            <div class="vuln-detail-section">
                <h4>Remediation</h4>
                <p>${vuln.remediation}</p>
            </div>
        `;

        modal.classList.remove('hidden');
    }

    closeModal() {
        document.getElementById('vulnModal').classList.add('hidden');
    }

    async startDeepAnalysis() {
        if (!this.currentTarget) {
            alert('Please set a target first');
            return;
        }

        await this.runBusinessLogicAnalysis();
        await this.runSessionAnalysis();
        await this.runApiAnalysis();
        await this.runErrorHandlingAnalysis();
    }

    async runBusinessLogicAnalysis() {
        const resultsEl = document.getElementById('businessLogicResults');
        resultsEl.innerHTML = '<div class="no-results pulse">Analyzing business logic...</div>';
        
        await this.delay(2500);
        
        const results = [
            {
                title: 'Price Manipulation',
                description: 'Product prices can be modified in client-side requests'
            },
            {
                title: 'Workflow Bypass',
                description: 'Multi-step processes can be completed out of order'
            },
            {
                title: 'Rate Limiting',
                description: 'No rate limiting detected on critical operations'
            }
        ];

        resultsEl.innerHTML = results.map(result => `
            <div class="analysis-result">
                <div class="analysis-title">${result.title}</div>
                <div class="analysis-description">${result.description}</div>
            </div>
        `).join('');
    }

    async runSessionAnalysis() {
        const resultsEl = document.getElementById('sessionResults');
        resultsEl.innerHTML = '<div class="no-results pulse">Analyzing session management...</div>';
        
        await this.delay(2000);
        
        const results = [
            {
                title: 'Session Fixation',
                description: 'Session ID not regenerated after authentication'
            },
            {
                title: 'Weak Session Tokens',
                description: 'Session tokens use predictable patterns'
            }
        ];

        resultsEl.innerHTML = results.map(result => `
            <div class="analysis-result">
                <div class="analysis-title">${result.title}</div>
                <div class="analysis-description">${result.description}</div>
            </div>
        `).join('');
    }

    async runApiAnalysis() {
        const resultsEl = document.getElementById('apiResults');
        resultsEl.innerHTML = '<div class="no-results pulse">Assessing API security...</div>';
        
        await this.delay(2200);
        
        const results = [
            {
                title: 'Missing Authentication',
                description: 'Several API endpoints accessible without authentication'
            },
            {
                title: 'Excessive Data Exposure',
                description: 'API returns more data than necessary for functionality'
            },
            {
                title: 'No Rate Limiting',
                description: 'API endpoints vulnerable to abuse and DoS attacks'
            }
        ];

        resultsEl.innerHTML = results.map(result => `
            <div class="analysis-result">
                <div class="analysis-title">${result.title}</div>
                <div class="analysis-description">${result.description}</div>
            </div>
        `).join('');
    }

    async runErrorHandlingAnalysis() {
        const resultsEl = document.getElementById('errorResults');
        resultsEl.innerHTML = '<div class="no-results pulse">Evaluating error handling...</div>';
        
        await this.delay(1800);
        
        const results = [
            {
                title: 'Information Disclosure',
                description: 'Stack traces and debug information exposed in error messages'
            },
            {
                title: 'Database Errors',
                description: 'Database error messages reveal schema information'
            }
        ];

        resultsEl.innerHTML = results.map(result => `
            <div class="analysis-result">
                <div class="analysis-title">${result.title}</div>
                <div class="analysis-description">${result.description}</div>
            </div>
        `).join('');
    }

    generateReport() {
        if (this.vulnerabilities.length === 0) {
            alert('No vulnerabilities found. Run a scan first.');
            return;
        }

        // Update vulnerability summary
        this.updateVulnerabilitySummary();
        
        // Update detailed findings
        const detailedFindings = document.getElementById('detailedFindings');
        detailedFindings.innerHTML = this.vulnerabilities.map(vuln => `
            <div class="vulnerability-card ${vuln.severity.toLowerCase()}" style="margin-bottom: 16px;">
                <div class="vuln-header">
                    <h4 class="vuln-title">${vuln.name}</h4>
                    <span class="severity-badge ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                </div>
                <div class="vuln-category">${vuln.category} • ${vuln.owasp}</div>
                <div class="vuln-description">${vuln.description}</div>
                <div style="margin-top: 12px;">
                    <strong>Location:</strong> ${vuln.location}<br>
                    <strong>CVSS Score:</strong> ${vuln.cvss}
                </div>
            </div>
        `).join('');

        alert('Security report generated successfully!');
    }

    updateVulnerabilitySummary() {
        const severityCounts = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };

        this.vulnerabilities.forEach(vuln => {
            const severity = vuln.severity.toLowerCase();
            if (severityCounts.hasOwnProperty(severity)) {
                severityCounts[severity]++;
            }
        });

        document.getElementById('criticalCount').textContent = severityCounts.critical;
        document.getElementById('highCount').textContent = severityCounts.high;
        document.getElementById('mediumCount').textContent = severityCounts.medium;
        document.getElementById('lowCount').textContent = severityCounts.low;
    }

    exportFindings() {
        if (this.vulnerabilities.length === 0) {
            alert('No findings to export. Run a scan first.');
            return;
        }

        const exportData = {
            target: this.currentTarget,
            vulnerabilities: this.vulnerabilities,
            reconData: this.reconData,
            exportDate: new Date().toISOString()
        };

        const dataStr = JSON.stringify(exportData, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `bughunter-findings-${this.currentTarget?.domain || 'export'}-${Date.now()}.json`;
        link.click();
        
        URL.revokeObjectURL(url);
        alert('Findings exported successfully!');
    }

    initializeMethodology() {
        const phasesEl = document.getElementById('methodologyPhases');
        
        phasesEl.innerHTML = this.methodology.map((phase, phaseIndex) => `
            <div class="methodology-phase">
                <div class="phase-header" onclick="app.togglePhase(${phaseIndex})">
                    <div>
                        <h3 class="phase-title">${phase.phase}</h3>
                        <p class="phase-description">${phase.description}</p>
                    </div>
                    <i class="fas fa-chevron-down phase-toggle"></i>
                </div>
                <div class="phase-content" id="phase-${phaseIndex}">
                    <ul class="phase-steps">
                        ${phase.steps.map((step, stepIndex) => `
                            <li class="phase-step" onclick="app.toggleStep(${phaseIndex}, ${stepIndex})">
                                <div class="step-checkbox" id="step-${phaseIndex}-${stepIndex}">
                                    <i class="fas fa-check" style="display: none;"></i>
                                </div>
                                <span class="step-text" id="text-${phaseIndex}-${stepIndex}">${step}</span>
                            </li>
                        `).join('')}
                    </ul>
                </div>
            </div>
        `).join('');
    }

    togglePhase(phaseIndex) {
        const header = document.querySelector(`#methodologyPhases .methodology-phase:nth-child(${phaseIndex + 1}) .phase-header`);
        const content = document.getElementById(`phase-${phaseIndex}`);
        
        header.classList.toggle('expanded');
        content.classList.toggle('expanded');
    }

    toggleStep(phaseIndex, stepIndex) {
        const checkbox = document.getElementById(`step-${phaseIndex}-${stepIndex}`);
        const text = document.getElementById(`text-${phaseIndex}-${stepIndex}`);
        const checkIcon = checkbox.querySelector('i');
        
        checkbox.classList.toggle('checked');
        text.classList.toggle('completed');
        
        if (checkbox.classList.contains('checked')) {
            checkIcon.style.display = 'block';
        } else {
            checkIcon.style.display = 'none';
        }
    }

    saveNotes() {
        this.currentNotes = document.getElementById('researchNotes').value;
        alert('Notes saved successfully!');
    }

    updateDashboardStats() {
        document.getElementById('activeScanCount').textContent = this.currentTarget ? '1' : '0';
        document.getElementById('vulnCount').textContent = this.vulnerabilities.length;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize the application
const app = new BugHunterPro();

// Global event listeners for modal
document.addEventListener('click', (e) => {
    if (e.target.id === 'vulnModal') {
        app.closeModal();
    }
});

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        app.closeModal();
    }
});

// Add some sample recent scans on load
document.addEventListener('DOMContentLoaded', () => {
    const recentScans = document.getElementById('recentScans');
    const sampleScans = [
        { target: 'example.com', date: '2 hours ago', status: 'Completed' },
        { target: 'testsite.org', date: '1 day ago', status: 'In Progress' },
        { target: 'demo.net', date: '3 days ago', status: 'Completed' }
    ];

    recentScans.innerHTML = sampleScans.map(scan => `
        <div class="scan-item">
            <div class="scan-info">
                <div class="scan-target">${scan.target}</div>
                <div class="scan-date">${scan.date}</div>
            </div>
            <div class="scan-status status--${scan.status === 'Completed' ? 'success' : 'warning'}">${scan.status}</div>
        </div>
    `).join('');
});