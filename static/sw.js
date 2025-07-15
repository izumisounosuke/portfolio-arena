// Service Workerのインストールイベント
self.addEventListener('install', (event) => {
    console.log('Service Worker: I am installed');
    // キャッシュを追加する処理などは、ここに追加していきます
});

// Service Workerのアクティベートイベント
self.addEventListener('activate', (event) => {
    console.log('Service Worker: I am active');
});

// フェッチイベント（ネットワークリクエストを横取りする）
self.addEventListener('fetch', (event) => {
    // 今回はキャッシュ戦略を実装しないので、何もしません。
    // これにより、オンライン時は通常通りネットワークリクエストが送られます。
});