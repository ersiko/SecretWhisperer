import cherrypy
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto import Random
import math
import redis

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

                        <button type="button" id="encrypt">Encrypt!</button>
                </form>
                <div id="output"></div>
                <form id="decrypt">
                        <p>
                                <label>Password or passphrase</label><br>
                                <input id="passwd" value="Secret Passphrase">
                        </p>
                        <p>
                                <label>Encrypted Secret</label><br>
                                <textarea id="encryptedsecret" style="width: 500px; height: 200px">here goes the encrypted secret message</textarea>
                        </p>

                        <button type="button" id="submit">Decrypt!</button>
                </form>
                <div id="output"></div>



<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.2/rollups/aes.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.1.1/jquery.min.js"></script>

    <script>
        $(function() {
            $("#encrypt").on("click", function() {
                var mysecret = document.forms["encrypt"]["secret"].value;
                var mypasswd = document.forms["encrypt"]["passwd"].value;
                var encryptedAES = CryptoJS.AES.encrypt(mysecret, mypasswd);
                console.log(encryptedAES.toString());
                $.ajax({type: "POST",
                    url: "http://ephemeral.tomas.cat:6543/encrypt?secret=" + encryptedAES.toString(), 
                    data: { id: $("#Shareitem").val(),
                            access_token: $("#access_token").val() },
                    success:function(result){
                            $("#output").html(result);
                }});
            });
            $("#decrypt").on("click", function() {
                var myEncryptedSecret = document.forms["decrypt"]["encryptedsecret"].value;
                var mypasswd = document.forms["decrypt"]["passwd"].value;
                var decrypted = CryptoJS.AES.decrypt(myEncryptedSecret, mypasswd);
                $("#output").html(decrypted.toString(CryptoJS.enc.Utf8));
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
            rc = myredis.set("ephemeral-" + url, encryptedSecret)
            return "<a href='/decrypt?url=" + url + "'>This is your url </a>."
                    
    @cherrypy.expose    
    def decrypt(self, url=""):
        myredis = redis.Redis()
        if url == "":
            return "There no secret there"
        else:
            obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
            cryptedSecret = myredis.get("ephemeral-" + url)
            if not cryptedSecret:
                return "There is no secret there"
            else:
                myredis.delete("ephemeral-" + url)
                decryptedSecret = obj.decrypt(cryptedSecret)
                return "Your decrypted secret is: " + decryptedSecret.decode()
    
    def random_url(self):
        randomString = Random.get_random_bytes(20)
        md5hash = MD5.new(randomString).hexdigest()
        return md5hash
        
if __name__ == '__main__':
    cherrypy.config.update({'server.socket_port': 6543, 'server.socket_host': '0.0.0.0'})
    cherrypy.quickstart(Ephemeral())
