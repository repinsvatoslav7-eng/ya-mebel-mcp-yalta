Я Мебель MCP Gateway — Ялта
Версия: v6.1-yalta-direct-safe-write

Сайт:
- Site ID: yalta-main
- URL: https://yamebel.pro

Фиксированный безопасный scope Яндекс Директа:
- Поиск Ялта: CampaignId 710957838
- РСЯ Ялта: CampaignId 710989135
- Поиск / группа Кухни: 5765010118
- РСЯ / группа Кухня: 5765233585
- Поиск / автотаргетинг: 205765010118
- РСЯ / автотаргетинг: 205765233585
- Поиск / рабочее объявление кухни: 17761831376
- РСЯ / рабочее объявление: 1916320049195790898

Безопасность Direct:
PREVIEW -> immutable plan -> explicit confirmation -> APPLY -> read-back verification.

В сервере сохранён универсальный Direct Safe Write v6:
- read Direct / Reports
- safe campaign updates
- safe ad-group updates
- safe keyword/autotargeting updates
- safe text-ad updates
- safe actions
- safe additions
- post-write verification

Ростовские фиксированные операции из этой Ялтинской сборки удалены.
Вместо них добавлены защищённые операции только для кампаний Ялты.

Render Environment:
YALTA_SITE_ID=yalta-main
YALTA_SITE_URL=https://yamebel.pro
YALTA_SHARED_SECRET=<новый Shared secret из WordPress Ялты>
YMB_REQUEST_TIMEOUT=20

Shared secret не хранить в GitHub и не отправлять в чат.

Build command:
pip install -r requirements.txt

Start command:
python server.py
