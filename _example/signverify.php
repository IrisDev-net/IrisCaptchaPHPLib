
<!DOCTYPE html>
<html lang="en">
<?PHP 

require "irisCaptcha.lib.php"; // download it from https://irisdev.net/public/lib/php/irisCaptcha.lib.php

$irisCaptchaPublicKey = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh+qPUxi6QYz7T22NdHcI
k3JxGQ4yzgaM+b+ReHHjnxy/o9FQ0bAU8B/jwAWGMAhtFoj6ERmbYEgWwUMy4yJ5
f0EFfrzcbSKkI+lr5LejyjocxxA5PI5tNLPTVrQMC/5kkHpylN5mTmcDFz3zT6EQ
EFJzJ+zRBdoQNIc3CW2WSA5vK2042iZRhOsbTWbxaP0TK+lqbcQSoWRAFBTOA4ZF
6PSTlO84p9M6/JkoyRPDYplVqXq+HMLs9uFHal3rN+KjQ2E7g0poFkvfXgGC0nUh
lMoLQBdSB1yT7oJc9Mua+/4Z1e1ma47d/kNxV+U5GjOfLHfqMo7xcfwocQ7ky+be
MQIDAQAB
-----END PUBLIC KEY-----";

$irisCaptcha = new IrisCaptcha("df059a421e1b5a2eac14d646114f816f342c04fdff84b063f81561b9e7dc62be0x2715",$irisCaptchaPublicKey);
?>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Test Iris Captcha</title>
</head>
<body style="padding:100px;">
    <?PHP
        if( isset($_POST["irisCaptcha"] )) {
            /**
             * function Check_Answer ( $response, $remoteip, $SignaturePreferration=false, $extra_params = array())
             * Check the user Response and return the value 
             *
             * @param string                    $response               The User Response
             * @param string                    $remoteip               The User IP - for security reasons it's necessary 
             * @param bool                      $SignaturePreferration  Specify that is validation with public key is preferred or not - if invalid Signature accored , it will try to check with server
             * @param array                     $extra_params           Extra parameters to send for irisdev server.
             *                                                  
             * 
             * 
             * @return object IrisCaptchaResponse  The Standard Response to check Status - get $IrisCaptchaResponse->is_valid (bool) | get $IrisCaptchaResponse->error (string)
             * 
             * * by setting $SignaturePreferration true , You will see how fast it is. but you need to set public key at object creation.
             * * also check you mailbox for advices about using public key verification.
             */
            $res = $irisCaptcha->Check_Answer($_POST["irisCaptcha"],$_SERVER['REMOTE_ADDR'],true);
            
            if ($res->is_valid) {
                // Captcha verified - continue ...
                echo "HOOOORAAAA";
            }else{
                echo $res->error;
            }

                
        }else{
        ?>
        
        <form Method="POST" action="" >
        <input name="Username" required type="text" placeholder="Username" />
        <input name="Password" required type="passowrd" placeholder="Password" />
        <button type="submit">Submit | Click Me!</button>
        <iris-captcha name="irisCaptcha" />
        </form>
        <?PHP   
        } 


    ?>


<?PHP
echo $irisCaptcha->Get_Js();
// or add it manually
?>
<!-- <script src="https://captcha.irisdev.net/js/0x2715?hoverScale=1.8"></script> -->
</body>
</html>

