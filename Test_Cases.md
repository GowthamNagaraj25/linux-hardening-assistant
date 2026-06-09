Test_Cases :
| Test Case ID | Scenario                  | Input                                     | Expected Output                                           | Result |
| ------------ | ------------------------- | ----------------------------------------- | --------------------------------------------------------- | ------ |
| TC01         | SSH Connection            | Valid Host, Username, Password, Port      | SSH connection established successfully                   | Pass   |
| TC02         | SSH Authentication        | Invalid Password                          | Display "Invalid username or password" message            | Pass   |
| TC03         | Host Unreachable          | Invalid/Unreachable IP Address            | Display "Target host cannot be reached" message           | Pass   |
| TC04         | SSH Timeout               | Host not responding within timeout period | Display "Connection timed out" message                    | Pass   |
| TC05         | Demo Mode                 | Enable Demo Mode                          | Display predefined audit results                          | Pass   |
| TC06         | Security Audit            | Run audit on connected Linux system       | Display audit findings and security score                 | Pass   |
| TC07         | SSH Root Login Check      | Linux system with root login enabled      | Detect and flag root login as a security issue            | Pass   |
| TC08         | Firewall Check            | UFW enabled on target machine             | Display firewall status as active                         | Pass   |
| TC09         | Fail2Ban Check            | Fail2Ban service running                  | Detect and display Fail2Ban status                        | Pass   |
| TC10         | Auditd Check              | Auditd service enabled                    | Detect and display Auditd status                          | Pass   |
| TC11         | Open Ports Detection      | Linux machine with active listening ports | Display list of open ports                                | Pass   |
| TC12         | Sudo Users Check          | Linux system containing sudo users        | Display users with administrative privileges              | Pass   |
| TC13         | PDF Report Generation     | Click "Export Report"                     | Generate and download PDF audit report                    | Pass   |
| TC14         | Fix Script Generation     | Click "Generate Fix Script"               | Generate downloadable fix.sh file                         | Pass   |
| TC15         | Gemini AI Analysis        | Gemini API Key configured                 | Display AI-generated recommendations                      | Pass   |
| TC16         | Local Recommendation Mode | Gemini API unavailable or quota exceeded  | Display local rule-based recommendations                  | Pass   |
| TC17         | Input Validation          | Empty Host/IP or Username fields          | Display validation error message                          | Pass   |
| TC18         | Security Score Generation | Complete audit execution                  | Generate score between 0–100 based on findings            | Pass   |
| TC19         | Docker Target Audit       | Audit Docker Ubuntu SSH container         | Successfully retrieve and analyze security configurations | Pass   |
| TC20         | Health Check API          | Access /api/health endpoint               | Return application health status                          | Pass   |
