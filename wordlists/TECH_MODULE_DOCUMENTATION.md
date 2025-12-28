# Technology Fingerprinting Module - Complete Documentation
## Comprehensive Web Technology Stack Detection for Redlense

### 📋 Overview
This module performs **comprehensive technology fingerprinting** on web applications, detecting web servers, frontend/backend frameworks, programming languages, CMS platforms, JavaScript libraries, analytics tools, CDNs, WAFs, databases, DevOps tools, cloud platforms, and third-party integrations.

---

## 🎯 Key Features

### 1. **External Wordlist System**
- **14 specialized wordlists** with 2,500+ technology signatures
- Easy to update without modifying code
- Located in `/wordlists/` directory
- Organized by category for maintainability

### 2. **Multi-Source Detection**
Detects technologies from:
- HTTP Headers
- Cookies
- HTML Content (meta tags, comments, inline code)
- JavaScript Files
- CSS Files
- Path Probing
- Server Responses
- Error Pages

### 3. **Advanced Analysis**
- Version extraction
- Confidence scoring (high/medium/low)
- Source tracking for each detection
- Deduplication and aggregation
- Technology categorization

---

## 📁 File Structure

```
Redlense/
├── Redlense.py                    # Main menu
├── modules/
│   └── tech.py                    # Technology Fingerprinting module
├── wordlists/
│   ├── tech_webservers.txt        # 100+ web servers
│   ├── tech_frontend.txt          # 300+ frontend frameworks & libraries
│   ├── tech_backend.txt           # 250+ backend frameworks
│   ├── tech_cms.txt               # 200+ CMS platforms
│   ├── tech_javascript.txt        # 400+ JS libraries
│   ├── tech_analytics.txt         # 300+ analytics & tracking tools
│   ├── tech_cdn.txt               # 150+ CDN providers
│   ├── tech_databases.txt         # 200+ database systems
│   ├── tech_programming.txt       # 100+ programming languages
│   ├── tech_devops.txt            # 400+ DevOps & CI/CD tools
│   ├── tech_cloud.txt             # 500+ cloud services (AWS, GCP, Azure, etc.)
│   ├── tech_plugins.txt           # 250+ plugins & extensions
│   ├── tech_ecommerce.txt         # 200+ ecommerce platforms & tools
│   └── tech_security.txt          # 300+ security tools & WAFs
└── Results/
    └── TechFingerprint_{hostname}_{timestamp}.txt
```

---

##  What Gets Detected

### Web Servers (100+)
```
nginx, Apache, IIS, LiteSpeed, Caddy, Tomcat, JBoss, WebLogic, 
WebSphere, Jetty, Gunicorn, uWSGI, Puma, Unicorn, Kestrel, 
HAProxy, Varnish, Squid, Traefik, Envoy, Kong, and more...
```

### Frontend Frameworks (300+)
```
React, Next.js, Vue, Nuxt, Angular, Svelte, SvelteKit, Ember, 
Backbone, Preact, Alpine.js, Lit, Material-UI, Ant Design,
Tailwind CSS, Bootstrap, Chakra UI, Three.js, D3.js, Chart.js,
GSAP, Framer Motion, Storybook, Webpack, Vite, and more...
```

### Backend Frameworks (250+)
```
Express, Koa, NestJS, Django, Flask, FastAPI, Ruby on Rails,
Laravel, Symfony, Spring Boot, ASP.NET Core, Gin, Echo, Actix,
Phoenix, Play Framework, Ktor, and more...
```

### CMS Platforms (200+)
```
WordPress, Drupal, Joomla, Magento, Shopify, Wix, Squarespace,
Webflow, Ghost, Strapi, Contentful, Sanity, Directus, Craft CMS,
ProcessWire, October CMS, Grav, and more...
```

### JavaScript Libraries (400+)
```
jQuery, Lodash, Moment.js, Axios, Socket.IO, RxJS, Handlebars,
Marked, Prism, Highlight.js, CodeMirror, Fabric.js, Konva,
Swiper, Owl Carousel, Leaflet, Mapbox, Quill, TinyMCE, and more...
```

### Analytics & Tracking (300+)
```
Google Analytics, GA4, GTM, Matomo, Hotjar, Mixpanel, Amplitude,
Heap, FullStory, Facebook Pixel, Segment, Adobe Analytics,
Crazy Egg, Optimizely, VWO, Kissmetrics, and more...
```

### CDN Providers (150+)
```
Cloudflare, Fastly, Akamai, Amazon CloudFront, Azure CDN,
KeyCDN, BunnyCDN, StackPath, Netlify CDN, Vercel, jsDelivr,
unpkg, cdnjs, and more...
```

### Databases (200+)
```
MySQL, PostgreSQL, MongoDB, Redis, Cassandra, Elasticsearch,
DynamoDB, Firestore, Neo4j, InfluxDB, CockroachDB, Supabase,
PlanetScale, Fauna, Snowflake, BigQuery, and more...
```

### Programming Languages (100+)
```
JavaScript, TypeScript, Python, PHP, Ruby, Java, Go, Rust,
Kotlin, Swift, Dart, Elixir, Scala, C#, C++, Perl, Lua,
Haskell, OCaml, and more...
```

### DevOps & CI/CD (400+)
```
Docker, Kubernetes, Jenkins, GitHub Actions, GitLab CI, CircleCI,
Terraform, Ansible, Helm, Istio, Linkerd, Prometheus, Grafana,
Datadog, New Relic, ArgoCD, Flux, Kong, Consul, and more...
```

### Cloud Platforms (500+)
```
AWS (EC2, S3, Lambda, RDS, CloudFront, EKS, etc.)
GCP (Compute Engine, Cloud Functions, GKE, BigQuery, etc.)
Azure (VMs, Functions, AKS, Cosmos DB, etc.)
Vercel, Netlify, Heroku, DigitalOcean, Linode, Fly.io,
Railway, Render, Cloudflare Workers, and more...
```

### Plugins & Extensions (250+)
```
WordPress plugins: Yoast SEO, Elementor, WooCommerce, Jetpack, ACF
Browser extensions: AdBlock, uBlock Origin, React DevTools, Vue DevTools
Chrome Extensions, Firefox Add-ons, and more...
```

### E-commerce (200+)
```
Platforms: Shopify, WooCommerce, Magento, BigCommerce, PrestaShop
Payments: Stripe, PayPal, Square, Braintree, Klarna, Afterpay
Tools: Klaviyo, Yotpo, ShipStation, ReCharge, Oberlo, and more...
```

### Security Tools (300+)
```
WAFs: Cloudflare WAF, AWS WAF, ModSecurity, Imperva, Fortinet
SSL: Let's Encrypt, DigiCert, Cloudflare SSL
Scanners: Nessus, Burp Suite, OWASP ZAP, Acunetix, Nuclei
Container: Aqua, Trivy, Falco, Snyk, Anchore, and more...
```

---

## Detection Methods

### 1. HTTP Header Analysis
Examines all response headers for technology indicators:
- `Server` header for web servers
- `X-Powered-By` for backend frameworks
- CDN-specific headers (CF-RAY, X-Amz-Cf-Id, etc.)
- Custom headers from frameworks

### 2. Cookie Analysis
Analyzes cookie names and values:
- `PHPSESSID` → PHP
- `JSESSIONID` → Java
- `ASP.NET_SessionId` → ASP.NET
- `laravel_session` → Laravel
- Framework-specific cookies

### 3. HTML Content Parsing
Scans HTML for patterns:
- `<meta name="generator">` tags
- Framework-specific attributes (ng-version, data-react, etc.)
- HTML comments with technology info
- Inline script patterns
- CSS class naming conventions

### 4. JavaScript Analysis
Examines JavaScript files and inline scripts:
- Script source URLs (jquery-3.6.0.min.js → jQuery 3.6.0)
- Global JavaScript objects (React, Vue, Angular, etc.)
- Library-specific code patterns
- Webpack/bundler artifacts
- Source map references

### 5. Path Probing
Tests technology-specific paths:
- `/wp-admin/` → WordPress
- `/admin/` → Various CMS
- `/_next/` → Next.js
- `/api/` → API frameworks
- Framework-specific endpoints

### 6. Analytics Detection
Identifies tracking and analytics:
- Google Analytics patterns (gtag, ga, analytics.js)
- Facebook Pixel (fbq)
- Tag managers (GTM, Segment)
- Heatmap tools (Hotjar, Crazy Egg)
- Marketing automation

### 7. CDN & WAF Detection
Detects protection layers:
- Cloudflare headers and cookies
- Akamai signatures
- AWS CloudFront indicators
- WAF challenge pages
- Security headers

---

## Scan Stages (9 Total)

1. **Fetch Page Content** - Retrieves HTML, scripts, stylesheets
2. **HTTP Header Analysis** - Examines all response headers
3. **Cookie Analysis** - Analyzes cookie patterns
4. **HTML Content Analysis** - Deep HTML parsing
5. **JavaScript Analysis** - JS library enumeration
6. **Analytics & Trackers** - Marketing tool detection
7. **Technology Path Probing** - Confirms via specific paths
8. **CDN & WAF Detection** - Security layer identification
9. **Aggregate Results** - Deduplication and organization

---

## Usage

### From Redlense Menu
```
Select option 5: Technology Fingerprinting
Enter target URL: https://example.com
```

### Standalone
```bash
python modules/tech.py https://example.com
```

### Output Location
```
Results/TechFingerprint_example_com_20241228_120000.txt
```

---

## Sample Output

```
Technology Stack Summary:

  Web Servers:
    • nginx v1.21.6 [high confidence]
    • Cloudflare [high confidence]

  Frontend Frameworks:
    • React v18.2.0 [high confidence]
    • Next.js v13.4.0 [high confidence]
    • Tailwind CSS v3.3.0 [high confidence]

  Backend Frameworks:
    • Node.js [high confidence]
    • Express [medium confidence]

  JavaScript Libraries:
    • Axios v1.4.0 [high confidence]
    • React Router v6.11.0 [high confidence]
    • Framer Motion [medium confidence]

  Analytics & Tracking:
    • Google Analytics 4 [high confidence]
    • Google Tag Manager [high confidence]
    • Hotjar [medium confidence]

  CDN Services:
    • Cloudflare [high confidence]
    • Vercel [high confidence]

  Cloud Platforms:
    • Vercel [high confidence]
    • AWS [medium confidence]

[✓] Total Technologies Detected: 24
[✓] High Confidence: 18
[✓] Versions Identified: 8
```

---

## Wordlist Format

Each wordlist follows a simple format:
```
# Category Comment
Technology Name
Another Technology
Technology v2
Variant Name
Alternate Spelling
```

### Example (tech_frontend.txt):
```
# Major Frontend Frameworks
React
ReactJS
React.js
Next.js
NextJS
Vue
Vue.js
VueJS
```

### Adding New Technologies
1. Open the appropriate wordlist file
2. Add the technology name (one per line)
3. Include common variations and spelling
4. Save the file
5. No code changes needed!

---

##  Confidence Scoring

### High Confidence
- Detected in HTTP headers
- Found in meta tags
- Confirmed via path probing
- Specific version extracted

### Medium Confidence
- Found in HTML content
- Detected in JavaScript
- Pattern matching

### Low Confidence
- Indirect indicators
- Partial matches
- Weak signals

---

##  Report Structure

The generated report includes:

1. **Technology Stack Summary**
   - Organized by category
   - Version information
   - Confidence levels

2. **Version Information**
   - All detected versions
   - Technology → Version mapping

3. **Statistics**
   - Total technologies detected
   - High confidence count
   - Versions identified
   - Category breakdown

---

## Coverage by Domain

### Gaming
```
Unity WebGL, Phaser, PlayCanvas, BabylonJS, PixiJS, Three.js,
Game servers, Gaming CDNs, Wowza, Red5
```

### Streaming
```
Video platforms, HLS, DASH, WebRTC, Media servers,
Video CDNs, Streaming protocols
```

### Crypto/Blockchain
```
Web3.js, Ethers.js, MetaMask, Phantom, WalletConnect,
Blockchain platforms, Smart contract frameworks
```

### AI/ML
```
TensorFlow.js, Brain.js, ml5.js, OpenAI, Anthropic,
AI platforms, Model serving, ML frameworks
```

### DevSecOps
```
CI/CD tools, Container security, SAST/DAST, Secret management,
Policy engines, Compliance tools, Security scanners
```

### Kubernetes
```
K8s, Helm, Istio, Linkerd, Prometheus, Grafana, ArgoCD,
Service meshes, Operators, Controllers
```

---

## Advanced Features

### 1. Parallel Scanning
- Uses ThreadPoolExecutor for speed
- 10 concurrent path probes
- Efficient resource usage

### 2. Version Extraction
- Regex patterns for version numbers
- Multiple detection methods
- Semantic version parsing

### 3. Deduplication
- Case-insensitive matching
- Variant detection
- Confidence aggregation

### 4. Source Tracking
- Records where each tech was found
- Multiple sources per technology
- Verification through cross-referencing

---

## Technology Categories

```
1.  web_servers              - Web servers & application servers
2.  frontend_frameworks      - UI frameworks & component libraries
3.  backend_frameworks       - Server-side frameworks
4.  programming_languages    - Languages detected
5.  cms                      - Content management systems
6.  javascript_libraries     - JS libs & utilities
7.  analytics                - Analytics & tracking
8.  cdn                      - Content delivery networks
9.  waf                      - Web application firewalls
10. databases                - Database systems
11. caching                  - Caching layers
12. authentication           - Auth systems
13. payment                  - Payment processors
14. devops                   - DevOps tools
15. cloud                    - Cloud platforms
16. containers               - Container tech
17. plugins                  - Plugins & extensions
18. other                    - Other technologies
```

---

## 🛠️ Customization

### Adding Custom Patterns
Edit `html_patterns` dict in `tech.py`:
```python
self.html_patterns = {
    'your_pattern': r'<pattern_regex>',
}
```

### Adding Cookie Patterns
Edit `cookie_patterns` dict:
```python
self.cookie_patterns = {
    'Technology': ['cookie1', 'cookie2'],
}
```

### Adding Probe Paths
Edit `probe_paths` dict:
```python
self.probe_paths = {
    'Technology': ['/path1', '/path2'],
}
```

---

## Performance

- **Typical scan time**: 15-30 seconds
- **Parallel probing**: 10 concurrent requests
- **Wordlist loading**: <1 second
- **2,500+ signatures** checked per scan
- **Efficient pattern matching**

---

## Security Considerations

- All requests made with verify=False (for testing)
- Uses standard User-Agent
- Respects robots.txt (when needed)
- Non-invasive scanning
- No exploitation attempts

---

## Dependencies

```python
requests
urllib.parse
colorama
re
json
os
concurrent.futures
```

Install:
```bash
pip install requests colorama
```

---

##  Use Cases

### For Penetration Testers
- Technology stack reconnaissance
- Version identification for exploit research
- Framework-specific attack vectors
- Third-party component discovery

### For Security Auditors
- Technology inventory
- Outdated version detection
- Unnecessary service exposure
- Attack surface mapping

### For Developers
- Competitor analysis
- Technology benchmarking
- Migration planning
- Stack validation

### For DevOps/SRE
- Infrastructure documentation
- Service discovery
- Technology drift detection
- Compliance verification

---

## Statistics

### Wordlist Coverage:
- **14 wordlist files**
- **2,500+ unique technologies**
- **48KB total wordlist size**
- **All major tech categories covered**

### Detection Capabilities:
- **Web Servers**: 100+ variants
- **Frontend**: 300+ frameworks/libraries
- **Backend**: 250+ frameworks
- **CMS**: 200+ platforms
- **JavaScript**: 400+ libraries
- **Analytics**: 300+ tools
- **Cloud**: 500+ services
- **DevOps**: 400+ tools
- **Security**: 300+ tools

---

##  Advantages

1. **External Wordlists** - Easy updates without code changes
2. **Comprehensive** - 2,500+ technology signatures
3. **Multi-Source** - 8 different detection methods
4. **Version Aware** - Extracts version numbers
5. **Confidence Scoring** - High/medium/low ratings
6. **Fast** - Parallel execution
7. **Organized** - Clear categorization
8. **Detailed Reports** - Comprehensive output
9. **Future-Proof** - Easy to extend
10. **Production-Ready** - Error handling & logging

---

##  Limitations

- Cannot detect obfuscated technologies
- Version extraction may be incomplete
- Passive detection only (no exploitation)
- Some technologies may require authenticated access
- False positives possible for generic patterns

---

##  Future Enhancements

Potential additions:
- [ ] Machine learning for pattern recognition
- [ ] Browser automation for JS-heavy sites
- [ ] Authenticated scanning
- [ ] API endpoint discovery
- [ ] Technology dependency mapping
- [ ] Vulnerability correlation
- [ ] JSON/CSV export formats
- [ ] Integration with other tools

---

## References

- Wappalyzer patterns
- BuiltWith detection methods
- WhatRuns database
- HTTPLeaks project
- Technology vendor documentation

---

##  Contributing

To add new technologies:
1. Identify the appropriate wordlist file
2. Add the technology name and variants
3. Test against known sites
4. Submit updates

---

**Created for Redlense**
**Module: Technology Fingerprinting**
**Version: 1.0**
**Date: December 2024**
**Wordlists: 14 files, 2,500+ signatures**
