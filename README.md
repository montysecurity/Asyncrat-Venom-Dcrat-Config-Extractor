# Asyncrat-Venom-Dcrat-Config-Extractor
Static Config Extractor for Asyncrat/Dcrat/VenomRat

Utilises dnlib to locate encrypted Config data and associated Encryption values. 
Values are decrypted in the script without emulating or executing malware code

 - Assumes config lies under the `Client.Settings` Class
 - Assumes Config is base64 encoded and AES256 encrypted.
 - Assumes most of the file is largely unobfuscated
 - Assumes the Aes256 Salt is stored as either a byte array (asyncrat) or a simple string (venom/dcrat)
 - Code for extracting the Byte array is a modified version of the code from OALabs/StormKitty (https://research.openanalysis.net/dot%20net/static%20analysis/stormkitty/dnlib/python/research/2021/07/14/dot_net_static_analysis.html)
 - 

# Example

`asyncrat-config-extractor.py asyncrat.bin`

# Samples

- Asyncrat: `4b63a22def3589977211ff8749091f61d446df02cfc07066b78d3302c034b0cc`
- Venom:    `2941774e26232818b739deff45e59a32247a4a5c8d1d4e4aca517a6f5ed5055f`
- Dcrat:    `ed7cd05b950c11d49a3a36f6fe35e672e088499a91f7263740ee8b79f74224e9`

# Output
![image](https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/assets/82847168/e0c20a33-1f3f-43b1-b4ec-b029f91de6c0)

![image](https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/assets/82847168/a505d5e9-16d7-4347-8493-b2ed20bbc935)


![image](https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/assets/82847168/ac016e16-317b-48c2-97c4-60a66460d849)


# Original Encrypted Values

![image](https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/assets/82847168/805841bb-9081-4509-9c09-344e50a68874)

![image](https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/assets/82847168/fb52c58c-eb4c-4217-ad39-ce8180e86c62)
