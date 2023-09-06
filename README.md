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

`decoder.py asyncrat.bin`

# Samples

- Async: `4b63a22def3589977211ff8749091f61d446df02cfc07066b78d3302c034b0cc`
- Venom: `2941774e26232818b739deff45e59a32247a4a5c8d1d4e4aca517a6f5ed5055f`
- Dcrat: `ed7cd05b950c11d49a3a36f6fe35e672e088499a91f7263740ee8b79f74224e9`

# Output
![image](https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/assets/82847168/37e62deb-6451-4c5c-a736-83e814542064)


![image](https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/assets/82847168/8bdf700b-40ed-470d-a00c-7c776820c858)

![image](https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/assets/82847168/036b56b0-fb71-4d46-ade7-0cd8a0e95444)

# Original Encrypted Values

![image](https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/assets/82847168/805841bb-9081-4509-9c09-344e50a68874)

![image](https://github.com/embee-research/Asyncrat-Venom-Dcrat-Config-Extractor/assets/82847168/fb52c58c-eb4c-4217-ad39-ce8180e86c62)
