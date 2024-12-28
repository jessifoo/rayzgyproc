# WordPress Security Hardening Plugin

A comprehensive security plugin designed for managing multiple WordPress sites on shared hosting. Focuses on malware prevention, health monitoring, and resource-efficient security scanning.

## Features

### Core Security Features
- Distributed security scanning across sites
- Malware detection and cleaning
- Obfuscated code detection
- File integrity monitoring
- Login protection
- IP management (blacklist/whitelist)

### Network Management
- Cross-site security coordination
- Shared resource management
- Distributed scanning schedule
- Unified threat intelligence
- Shared API rate limits

### Health Monitoring
- System resource tracking
- Performance optimization
- Database health checks
- File permission monitoring
- Core file integrity checks

### Optimization Features
- Hostinger Optimizations: Specific for Hostinger hosting
- WordPress Optimizations: Core WP performance
- Database Cleaner: DB optimization and cleanup

## Plugin Structure

```
wp-security-hardening/
├── admin/
│   ├── class-security-dashboard.php    # Main admin dashboard
│   ├── class-security-settings.php     # Plugin settings page
│   ├── security-dashboard.php          # Dashboard template
│   ├── security-test.php              # Security testing tools
│   ├── css/                           # Admin styles
│   │   └── admin.css
│   └── js/                            # Admin scripts
│       └── admin.js
├── includes/
│   ├── class-ai-security.php          # AI-powered security features
│   ├── class-code-analyzer.php        # Code analysis tools
│   ├── class-core-repair.php          # WordPress core file repair
│   ├── class-cron-manager.php         # Scheduled tasks manager
│   ├── class-db-cleaner.php           # Database optimization
│   ├── class-distributed-scanner.php   # Multi-site scanner
│   ├── class-file-integrity.php       # File monitoring
│   ├── class-file-monitor.php         # Real-time file changes
│   ├── class-health-monitor.php       # System health tracking
│   ├── class-hostinger-optimizations.php # Hostinger-specific optimizations
│   ├── class-ip-manager.php           # IP management
│   ├── class-logger.php               # Centralized logging
│   ├── class-login-hardening.php      # Login security
│   ├── class-malware-cleaner.php      # Malware removal
│   ├── class-notifications.php        # Alerts and reports
│   ├── class-pattern-updater.php      # Security pattern updates
│   ├── class-plugin-integrations.php  # Plugin compatibility
│   ├── class-quarantine-manager.php   # Infected file isolation
│   ├── class-rate-limiter.php         # API rate limiting
│   ├── class-security-scanner.php     # Core security scanner
│   ├── class-site-coordinator.php     # Multi-site coordination
│   ├── class-site-network.php         # Network management
│   ├── class-threat-apis.php          # External API integrations
│   ├── class-threat-intelligence.php   # Threat detection
│   ├── class-virustotal-scanner.php   # VirusTotal integration
│   ├── class-wp-optimizations.php     # WordPress optimizations
│   └── class-yara-scanner.php         # YARA pattern matching
├── data/
│   ├── configs/                       # Default configurations
│   └── patterns/                      # Security patterns and rules
├── migrations/                        # Database updates
├── rules/                            # Security rules
├── templates/
│   ├── email/                        # Email notification templates
│   └── reports/                      # Security report templates
├── tests/                            # Unit tests
└── wp-security-hardening.php         # Main plugin file

```

## Component Descriptions

### Core Components
- **Security Dashboard**: Central interface for all security features
- **Distributed Scanner**: Coordinates scans across multiple sites
- **Health Monitor**: Tracks system health and performance
- **Site Coordinator**: Manages resource sharing between sites
- **Rate Limiter**: Controls API usage across sites
- **Logger**: Centralized logging system
- **Notifications**: Alerts and reporting system
- **Cron Manager**: Scheduled tasks coordinator

### Security Features
- **Malware Cleaner**: Detects and removes malware
- **Code Analyzer**: Identifies suspicious code patterns
- **File Monitor**: Tracks file changes in real-time
- **IP Manager**: Handles IP blocking and whitelisting
- **Login Hardening**: Protects against brute force attacks
- **YARA Scanner**: Pattern-based malware detection
- **VirusTotal Scanner**: File reputation checking
- **Pattern Updater**: Keeps security rules current

### Network Features
- **Site Network**: Manages multi-site connections
- **Threat Intelligence**: Shares security data between sites
- **Plugin Integrations**: Handles compatibility with other plugins
- **Core Repair**: Fixes WordPress core file issues
- **Quarantine Manager**: Isolates suspicious files

## Project Roadmap and Progress

### Phase 1: Hostinger Optimization (In Progress)
- [x] YARA Scanner Implementation
- [x] File Change Monitoring
- [x] Infection Tracing System
- [ ] LiteSpeed Cache Integration
- [ ] PHP Worker Optimization
- [ ] Memory Limit Management
- [ ] MySQL Query Optimization
- [ ] File Permission Handler

### Phase 2: Advanced Security (Pending)
- [ ] Web Application Firewall (WAF)
- [ ] Real-time IP Reputation System
- [ ] Dynamic Code Analysis
- [ ] Secure Cookie Management
- [ ] Advanced XSS Protection
- [ ] CSRF Token Management
- [ ] SQL Injection Prevention

### Phase 3: Performance Integration (Pending)
- [ ] Database Cleanup Automation
- [ ] Cache Management System
- [ ] Asset Optimization
- [ ] Query Performance Monitor
- [ ] Resource Usage Tracker
- [ ] Load Balancer
- [ ] Backup Manager

### Phase 4: Attack Vector Protection (Pending)
- [ ] wp-config.php Protection
- [ ] Upload Directory Security
- [ ] Theme/Plugin Editor Monitor
- [ ] File Ownership Tracker
- [ ] PHP Execution Blocker
- [ ] Directory Traversal Prevention
- [ ] Remote File Inclusion Protection

### Phase 5: Network Security (Pending)
- [ ] Cross-site Request Validator
- [ ] API Rate Limiter
- [ ] Shared Hosting Isolator
- [ ] Database Connection Security
- [ ] SSL/TLS Enforcer
- [ ] HTTP Security Headers
- [ ] Content Security Policy

### Phase 6: Monitoring and Reporting (Pending)
- [ ] Real-time Security Dashboard
- [ ] Email Alert System
- [ ] Performance Reports
- [ ] Security Audit Logs
- [ ] Network Status Monitor
- [ ] Resource Usage Reports
- [ ] Threat Intelligence Reports

## Current Focus (Phase 1)

### Hostinger-Specific Features
1. **LiteSpeed Optimization**
   - Custom cache rules
   - ESI implementation
   - Edge security rules
   - Cache purge automation

2. **Resource Management**
   - PHP worker monitoring
   - Memory usage optimization
   - CPU load balancing
   - I/O operation limiting

3. **Database Optimization**
   - Query caching
   - Table optimization
   - Connection pooling
   - Index management

4. **File System Security**
   - Permission automation
   - Ownership management
   - Access control
   - Directory protection

### Implementation Progress

#### December 27, 2024
- Implemented YARA scanner with resource-aware scheduling
- Added file change monitoring system
- Created infection tracing system
- Enhanced malware pattern detection
- Implemented zero-byte file cleanup

#### Next Steps
1. Implement LiteSpeed Cache integration
2. Add PHP worker optimization
3. Configure memory limit management
4. Optimize MySQL queries
5. Add file permission handler

## Recent Updates

### Auto-Repair System (2024-12-27)
- **Core Auto-Repair**
  - Daily scheduled checks with site-specific timing
  - Prioritized critical file verification
  - Deep file analysis with permission and content checks
  - Automatic restoration from WordPress.org

- **Plugin Auto-Repair**
  - Daily checks offset from core checks
  - Priority-based plugin scanning
  - Enhanced verification with suspicious pattern detection
  - Automatic clean file restoration

- **Resource Management**
  - Shared API rate limits across sites
  - Staggered checks to distribute load
  - Smart caching of checksums
  - Efficient file verification

### Threat Intelligence
- **YARA Integration**
  - Custom WordPress-specific YARA rules
  - Malware pattern detection
  - Obfuscated code identification
  - Shell and backdoor detection

- **Pattern Matching**
  - Base64 decode detection
  - Malicious function detection
  - Hidden PHP code detection
  - Injection attempt identification

### Safety Features
- File quarantine before modifications
- Backup of critical database tables
- Site state preservation
- Automatic rollback on issues

## Usage

### Auto-Repair
The plugin automatically:
1. Checks core files daily at site-specific times
2. Verifies plugin files 12 hours offset from core
3. Prioritizes security-critical components
4. Maintains detailed repair logs

### Threat Detection
1. Uses YARA rules for pattern matching
2. Monitors file changes in real-time
3. Checks for known malware signatures
4. Identifies suspicious code patterns

### Installation
1. Install plugin on all WordPress sites
2. Configure network settings
3. Set up site coordination
4. Configure scanning schedule

### Network Setup
1. Install on primary site first
2. Add additional sites in Settings
3. Verify network connection
4. Configure shared resources

### Security Monitoring
1. View security status in Dashboard
2. Monitor resource usage
3. Check scan results
4. Review threat reports

## API Rate Limits

The plugin shares API rate limits across all sites:
- File scans: 500/day
- IP checks: 1000/day
- Threat lookups: 100/hour

## Resource Management

- Distributes scans across 24 hours
- Monitors shared hosting limits
- Coordinates heavy operations
- Shares security findings

## Cache Management

Located in `wp-content/security-cache/`:
- Scan results
- Threat signatures
- IP blacklists
- Operation logs

## Requirements

- WordPress 5.0+
- PHP 7.4+
- Write access to wp-content
- Shared hosting compatible
- No external API keys required

## Support

For issues or questions:
1. Check the admin dashboard
2. Review operation logs
3. Check network status
4. Monitor resource usage

## Best Practices

1. **Regular Monitoring**
   - Check dashboard daily
   - Review security reports
   - Monitor resource usage

2. **Network Management**
   - Keep sites in sync
   - Monitor API usage
   - Review shared findings

3. **Resource Usage**
   - Schedule heavy tasks
   - Monitor hosting limits
   - Coordinate operations

## Resource Limits

### API Limits (Shared Across Sites)
- VirusTotal API: 500 requests/day
- IP Reputation: 1000 checks/day
- Malware DB: 100 queries/hour
- WordPress.org API: 100 requests/hour

### System Resources
- Max Memory: 256MB per process
- Max Execution: 30 seconds
- Max Files: 1000 per scan
- Max File Size: 5MB for scanning

### Database Limits
- Max Connections: 10 per site
- Max Query Time: 5 seconds
- Max Result Size: 1MB
- Query Cache: 50MB

## Monitoring Metrics

### Performance
- PHP worker usage
- Memory consumption
- Database connections
- Cache hit ratio
- API usage

### Security
- File changes
- Login attempts
- Malware detections
- API requests
- Resource usage

### Network
- Cross-site requests
- API response times
- SSL/TLS status
- DNS resolution
- Connection errors
