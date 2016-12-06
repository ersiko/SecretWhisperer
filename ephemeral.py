import cherrypy
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto import Random
from requests.utils import quote
import math
import redis

secretTTL = 3600

class Ephemeral(object):
    
    @cherrypy.expose
    def index(self):
        return """<!doctype html>
<html>
        <body lang="en">
                <form id="encrypt">
                        <p>
                                <label>Password or passphrase</label><br>
                                <input id="passwd" value="Secret Passphrase">
                        </p>
                        <p>
                                <label>Secret</label><br>
                                <textarea id="secret" style="width: 500px; height: 200px">This is the secret message</textarea>
                        </p>

                        <button type="button" id="submit">Encrypt!</button>
                </form>
                <div id="output"></div>


<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/aes.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.1.1/jquery.min.js"></script>
    <script>
        $(function() {
            $("#submit").on("click", function() {
                var mysecret = document.forms["encrypt"]["secret"].value;
                var mypasswd = document.forms["encrypt"]["passwd"].value.trim();
                var encryptedAES = CryptoJS.AES.encrypt(mysecret, mypasswd);
                console.log(encryptedAES.toString());
                $.post("encrypt", 
                       {"secret": encryptedAES.toString()}, 
                       function(result){
                            $("#output").html(result);
                       }
                );
            });
        });
    </script>
</body>
</html>
"""
    @cherrypy.expose
    def encrypt(self, secret=""):
        myredis = redis.Redis()
        if secret == "":
            return "No secret introduced"
        else:
            paddedLength = math.ceil(len(secret) / 16) * 16
            paddedSecret = secret.ljust(paddedLength, ' ')
            
            obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
            encryptedSecret = obj.encrypt(paddedSecret)
            url = self.random_url()
            rc = myredis.setex("ephemeral-" + url, encryptedSecret, secretTTL)
            return "<a href='/" + url + "'>This is your url </a>."
                    
    @cherrypy.expose    
    def decrypt(self, url=""):
        myredis = redis.Redis()
        if url == "":
            return "There no secret there"
        else:
            obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
            cryptedSecret = myredis.get("ephemeral-" + url)
            if not cryptedSecret:
                return "There is no secret there"
            else:
                myredis.delete("ephemeral-" + url)
                decryptedSecret = obj2.decrypt(cryptedSecret)
                return decryptedSecret
    
    @cherrypy.expose
    def default(self,*args,**kwargs):
        myredis = redis.Redis()
        secretID = cherrypy.request.path_info[1:]
        if not myredis.exists("ephemeral-" + secretID):
            return("There's no secret here")
        else: 
            return """<!doctype html>
        <html>
                <body lang="en">
Someone sent you a secret, right? You better have the passphrase to decrypt it, too!
                                <form id="decrypt">
                        <p>
                                <label>Password or passphrase </label><br>
                                <input id="passwd" value="Secret Passphrase">
                        </p>
                        <button type="button" id="submit">Decrypt!</button>
                </form>
                <div id="output"></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/aes.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.1.1/jquery.min.js"></script>
    <script>
            $(function() {
                $("#submit").on("click", function() {
                    var mypasswd = document.forms["decrypt"]["passwd"].value.trim();
                    $.post("decrypt", 
                          { 'url': '""" + secretID + """' },
                          function(result) {
                            if (result == "There is no secret there") {
                                $("#output").html(result)
                            } else {
                                var decrypted = CryptoJS.AES.decrypt(decodeURI(result), mypasswd).toString(CryptoJS.enc.Utf8)
                                $("#output").html("Your secret is </br></br><b> " + decrypted + "</b></br></br>Now the secret has been erased. It was ephemeral, it no longer exists.");
                            }
                          }                            
                    );
                });                                                                                    
            });  
    </script>
</body>
</html>
"""
                        
            
            
    def random_url(self):
        randomString = Random.get_random_bytes(20)
        md5hash = MD5.new(randomString).hexdigest()
        return md5hash
        
if __name__ == '__main__':
    cherrypy.config.update({'server.socket_port': 6543, 'server.socket_host': '0.0.0.0'})
    cherrypy.quickstart(Ephemeral())
