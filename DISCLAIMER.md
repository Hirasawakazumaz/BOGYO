# Disclaimer

**Read this before using Sentinel-Guard.**

1. **No warranty.** The software is provided "AS IS", without warranty of any kind,
   express or implied, including merchantability, fitness for a particular purpose,
   and non-infringement. You use it entirely at your own risk.

2. **Authorized use only.** This software is intended **solely** for defending and
   testing systems that you own or are explicitly authorized (in writing) to test.
   Using it against any other system may be illegal.

3. **No liability.** To the maximum extent permitted by law, the authors and
   contributors are not liable for any direct, indirect, incidental, special,
   consequential, or exemplary damages — including data loss, service disruption,
   lost profits, system damage, or legal consequences — arising from use or misuse
   of this software, even if advised of the possibility of such damages.

4. **You are responsible for compliance.** You are solely responsible for complying
   with all applicable laws and regulations, including but not limited to Japan's
   Unauthorized Computer Access Act and Penal Code Articles 168-2/168-3 and 234-2,
   the US Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, Germany's
   StGB §202c, and the Council of Europe Convention on Cybercrime, as well as any
   contracts, hosting-provider terms, and organizational policies that apply to you.

5. **Not legal or security advice.** Documentation (including the whitepaper) is an
   engineering description, not legal or professional security advice. Consult
   qualified professionals for your situation.

6. **Automated actions.** When you enable capabilities and disable dry-run, the
   software can modify firewall rules and configuration files and can act on a
   schedule. You are responsible for reviewing and approving these actions and for
   maintaining backups. Test in a safe environment first.

7. **Cryptography & mesh.** The mesh's rolling-key channel and machine-bound key
   are a pragmatic design built on standard primitives for a trusted set of your
   own nodes; they are **not** a formally verified protocol and do not provide
   hardware key non-extraction. Do not rely on them as your sole security control.

8. **No endorsement.** Use of third-party tools (nmap, nuclei, OWASP ZAP, trivy,
   Docker, LLM providers) is subject to their own licenses and terms.

By using the software you accept this disclaimer and the [TERMS_OF_USE](TERMS_OF_USE.md).
