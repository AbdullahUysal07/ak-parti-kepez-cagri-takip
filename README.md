# AK Parti Kepez Üye Çağrı Takip

Site (`index.html`) GitHub'a her push'ta Cloudflare'de otomatik yayınlanır.
Sunucu tarafı `cloudflare-worker/` klasöründeki `ak-parti-kepez-push` worker'ıdır.

## Güvenlik

- Üye listesi, mahalle başkanları ve kullanıcı bilgileri **bu repoda tutulmaz**.
  Hepsi Cloudflare KV'de durur; sunucu yalnızca giriş yapmış kullanıcıya,
  yetkili olduğu kısmı gönderir (mahalle başkanı yalnızca kendi mahallesini görür).
- TC kimlik numaraları sunucuya hiç gönderilmez. Excel yüklenirken tarayıcıda,
  geri çevrilemez bir koda dönüştürülür ve hiçbir ekranda gösterilmez.
- Ortak başlangıç şifresiyle giren kullanıcılardan kendi şifrelerini belirlemeleri istenir.

## Worker'ı yayına alma

```
cd cloudflare-worker
npx wrangler deploy
```

İlk kurulumda kullanıcı ve başkan listeleri bir kez KV'ye yüklenir
(dosyalar repoda değildir, ayrıca verilir):

```
npx wrangler kv key put --binding SUBSCRIPTIONS --remote "__users__" --path users-seed.json
npx wrangler kv key put --binding SUBSCRIPTIONS --remote "__leaders__" --path leaders-seed.json
```

## Üye listesini güncelleme

Hasan Demir Paneli → **Üye Listesi Yükle** sekmesinden AKBİS Excel dosyası seçilir.
Listede olmayan üyeler kaldırılır, yeni üyeler eklenir; panelden yapılan
telefon/adres düzenlemeleri korunur.
