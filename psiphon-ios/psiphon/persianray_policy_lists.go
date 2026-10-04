package psiphon

// Fallback host lists if the iOS client omits PersianRay* arrays.
// The release source of truth is persianray-ios PolicyDomains.swift /
// LocalBypassDomains. The app injects those into the Psiphon JSON on connect.

var persianRaySafeSearchExact = []string{
	"www.google.com", "google.com", "www.google.co.uk", "www.google.de",
	"www.google.fr", "www.google.ca", "www.google.com.au", "www.google.co.jp",
	"www.google.com.br", "www.google.co.in", "www.google.ru", "www.google.it",
	"www.google.es", "www.google.nl", "www.google.com.tr", "www.google.ae",
	"www.google.com.sa", "www.google.co.ir",
	"www.youtube.com", "m.youtube.com", "youtube.com", "youtu.be",
	"www.youtube-nocookie.com",
}

var persianRayDoHExact = []string{
	"dns.google.com", "mozilla.cloudflare-dns.com", "chrome.cloudflare-dns.com",
}

var persianRayDoHSuffix = []string{
	"dns.google", "cloudflare-dns.com", "dns.quad9.net", "dns.adguard.com",
	"dns.adguard-dns.com", "doh.opendns.com", "doh.cleanbrowsing.org",
}

var persianRayAdExact = []string{
	"analytics.google.com", "click.googleanalytics.com", "tagmanager.google.com",
	"pagead.l.doubleclick.net", "imasdk.googleapis.com", "dai.google.com",
	"pixel.facebook.com", "an.facebook.com", "tr.facebook.com",
	"ads.linkedin.com", "px.ads.linkedin.com", "analytics.twitter.com",
	"ads.x.com", "ads.tiktok.com",
}

var persianRayAdSuffix = []string{
	"doubleclick.net", "googlesyndication.com", "googleadservices.com",
	"googletagservices.com", "googletagmanager.com", "google-analytics.com",
	"googleanalytics.com", "adservice.google.com", "app-measurement.com",
	"amazon-adsystem.com", "criteo.com", "criteo.net", "taboola.com",
	"outbrain.com", "adnxs.com", "applovin.com", "unityads.unity3d.com",
	"ads-twitter.com", "connect.facebook.net", "sc-static.net",
	"hotjar.com", "mixpanel.com", "amplitude.com", "segment.io",
	"appsflyer.com", "adjust.com", "branch.io", "samsungads.com",
	"ad.xiaomi.com", "ads.huawei.com",
}

var persianRayAdultExact = []string{}

var persianRayAdultSuffix = []string{
	"pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "xhamster.desi",
	"redtube.com", "youporn.com", "tube8.com", "spankbang.com", "chaturbate.com",
	"onlyfans.com", "stripchat.com", "bongacams.com", "cam4.com",
	"missav.com", "javdb.com", "avgle.com", "hqporner.com", "thisvid.com",
	"rule34.xxx", "nhentai.net", "hanime.tv",
}

var persianRayLocalSuffix = []string{
	"ir", "xn--mgba3a4f16a",
	"digikala.com", "digi-kala.com", "divar.ir", "divar.cloud", "divarcdn.com",
	"snapp.ir", "snapp.taxi", "snapp.cab", "snappfood.ir", "snapp.site",
	"aparat.com", "filimo.com", "varzesh3.com", "cafebazaar.org",
	"zarinpal.com", "blubank.com", "shaparak.ir", "bmi.ir",
	"sheypoor.com", "torob.com", "okala.com", "janebi.com",
	"eitaa.com", "bale.ai", "rubika.ir",
	"telewebion.com", "cinematicket.org",
	"arvancloud.com", "parsonline.com", "iranserver.com",
	"mehrnews.com", "farsnews.ir", "isna.ir", "tasnimnews.com",
	"bankmelli-iran.com", "agri-bank.com", "mellatinsurance.com",
}
