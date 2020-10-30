
<!DOCTYPE html>
<html lang="en">
<?PHP 

require "irisCaptcha.lib.php";

$irisCaptcha = new IrisCaptcha("df059a421e1b5a2eac14d646114f816f342c04fdff84b063f81561b9e7dc62be0x2715");
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
             */
            $res = $irisCaptcha->Check_Answer($_POST["irisCaptcha"],$_SERVER['REMOTE_ADDR'],false);
            
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
<!-- <script src="https://captcha.irisdev.net/js/{{Your Uniq ID}}?hoverScale=1.8"></script> -->
</body>
</html>

