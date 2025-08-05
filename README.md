# AES_128bitPython
AES algoritmasının 128 bitlik anahtar ile şifrelenmesi ve şifrenin çözülmesi
AES algoritması 128 bit blok uzunluğuna sahiptir. 16 byte lık bloklar üzerinde gerçeklenir. Girişteki her bir byte 4x4 lük AES durum matrisinin bir hücresine yerleştiriliyor. İşlemlerden sonra en son matristeki byte değerleri birleştirilerek algoritma çıkışı elde edilmiş oluyor. 128 bit anahtar kullanılıyorsa bu algoritma 10 tur da gerçekleşebilir.
AES algoritması her round u 4 işlemden oluşan 10 rounddan meydana gelir. Başlangıçta AddRoundKey yapılmak üzere her round SubBytes, ShiftRows, MixColums ve AddRoundKey adımlarından oluşur. Son tur da MixColums işlemi yapılmaz.
Şifre çözme algoritmasında ise bu işlemleri tersten olacak şekilde ilerletiriz.
Tur Anahtarı Oluşturma (Key Schedule): Kelime tabanlı gerçekleştirir. AES algoritması için her round için ayrı bir anahtar üretilir. Şifre çözme sürecinde üretilen anahtarlar tekrar kullanılır.
Bu çalışmayı bilgisayarınızda çalıştırmanız için tüm dosyaları githubda yüklenmiş olduğu şekliyle dosyalamanız gerekmektedir.
