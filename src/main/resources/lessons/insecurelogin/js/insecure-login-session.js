function start_secure_login() {
    var request = new XMLHttpRequest();
    request.open('POST', 'InsecureLogin/login', true);
    request.send();
}
