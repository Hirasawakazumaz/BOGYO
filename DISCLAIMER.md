# Disclaimer / 免責事項

**Read this before using Sentinel-Guard. 使用前に必ずお読みください。**

## English

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

## 日本語

1. **無保証。** 本ソフトは現状有姿（AS IS）で提供され、商品性・特定目的適合性・非侵害を
   含むいかなる明示黙示の保証もありません。利用は完全に自己責任です。

2. **認可された利用のみ。** 本ソフトは、自分が所有、または書面で明示的にテスト許可を得た
   システムの防御・テストに**のみ**用いることを意図しています。それ以外への使用は違法と
   なり得ます。

3. **免責。** 法が許す最大限の範囲で、作者および貢献者は、本ソフトの使用または誤用から
   生じるいかなる直接・間接・付随的・特別・結果的・懲罰的損害（データ損失、サービス停止、
   逸失利益、システム損傷、法的責任を含む）についても、責任を負いません。

4. **順守は利用者の責任。** 不正アクセス禁止法、刑法168条の2・168条の3・234条の2、米CFAA、
   英Computer Misuse Act、独StGB§202c、サイバー犯罪条約（ブダペスト条約）等の関連法令、
   および適用される契約・ホスティング規約・組織ポリシーの順守は、すべて利用者の責任です。

5. **法的・専門的助言ではない。** ドキュメント（ホワイトペーパーを含む）は技術的な説明で
   あり、法的助言やセキュリティの専門的助言ではありません。個別事情は専門家にご相談ください。

6. **自動動作。** 機能を有効化し dry-run を解除すると、ファイアウォール規則や設定ファイルを
   変更し、定期実行もし得ます。これらの確認・承認・バックアップは利用者の責任です。まず安全な
   環境で試してください。

7. **暗号とメッシュ。** メッシュのローリング鍵通信とマシン束縛鍵は、信頼できる自分のノード群
   向けに標準的な暗号要素で構成した実用的設計であり、**形式検証済みプロトコルではなく**、
   ハードウェアによる鍵非抽出も提供しません。唯一のセキュリティ対策として依存しないでください。

8. **第三者ツール。** nmap・nuclei・OWASP ZAP・trivy・Docker・LLM事業者等の利用は、各々の
   ライセンス・規約に従います。

本ソフトを使用した時点で、本免責事項と[利用規約](TERMS_OF_USE.md)に同意したものとみなします。
