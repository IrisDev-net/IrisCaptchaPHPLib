# IrisCaptchaPHPLib
[![IrisDev](https://github.com/rahmaniali-ir/rahmaniali.ir/blob/master/irisdev.png?raw=true)][iris]
v1.0.0

### What is IrisCaptchaPHPLib?
IrisCaptchaPHPLib is a PHP library to validate results provided by IrisCaptcha web component.
You can get more information about IrisCaptcha from [irisdev.net][iris]

### How to use it?
  - Include or require "irisCaptcha.lib.php" file
  - Use "Check_Answer" function to validate the answer
  - Act accordingly to the answer

### Installation

```sh
$ git clone https://github.com/IrisDev-net/IrisCaptchaPHPLib.git
```

You can also download the a file of the library form [Here][zip]

### Parameters
The checker function accepts some parameters as below:

| Name | Required | Type | Default Value | Description |
| ---- | -------- | ---- | ------------- | ----------- |
| response | Yes | String | - | The response comes from server |
| remoteip | Yes | String | - | The IP?!! |
| SignaturePreferration | No | Boolean | False | The Sig |
| extra_params | No | Array | [] | In case you want to provide extra options |

   [iris]: <http://irisdev.net/>
   [zip]: <https://github.com/IrisDev-net/IrisCaptchaPHPLib/archive/main.zip>
