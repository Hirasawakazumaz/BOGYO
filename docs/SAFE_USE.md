# Safe-Use Request / 安全利用のお願い

This project is shared in the hope it helps people defend **their own** systems.
Please use it in that spirit. / 本プロジェクトは、利用者が**自分自身の**システムを守る
助けになることを願って公開しています。その精神でご利用ください。

## Please DO / お願いします
- Use it only on hosts and networks **you own or are explicitly authorized (in
  writing) to test**, declared in your signed scope.
  自分が所有、または書面で明示的にテスト許可を得た資産のみを対象にし、署名スコープに宣言する。
- Keep `dry_run` on and capabilities off until you have reviewed what each does.
  各機能を理解するまで `dry_run` を有効・各機能を無効のままにする。
- Keep real action (blocking, patch apply, attack validation) behind human review.
  実際の遮断・パッチ適用・攻撃検証は人のレビューを通す。
- For the server mesh, connect **only your own servers** running this software.
  メッシュは、本ソフトを入れた**自分のサーバー同士**だけで接続する。
- Keep your private keys (`config/*.key`, node key) secret and backed up safely.
  秘密鍵は秘匿し、安全にバックアップする。

## Please DO NOT / おやめください
- Do not point it at anyone else's systems, or "hack back" an attacker.
  他者のシステムに向けたり、攻撃元へ反撃（ハックバック）したりしない。
- Do not run attack validation against production — use an isolated sandbox.
  本番へ攻撃検証をしない（隔離サンドボックスを使う）。
- Do not remove, disable, or circumvent the safeguards, or redistribute a build
  with them weakened. 安全機構を除去・無効化・回避したり、弱めた版を再配布しない。

## If in doubt / 迷ったら
Stop and ask a qualified security professional and, where relevant, a lawyer. The
defaults are conservative on purpose; keep them that way unless you are sure.
不明なときは専門家（必要なら弁護士）に相談を。既定値は意図的に保守的です。

See [../TERMS_OF_USE.md](../TERMS_OF_USE.md), [../DISCLAIMER.md](../DISCLAIMER.md),
and [legal.md](legal.md).
