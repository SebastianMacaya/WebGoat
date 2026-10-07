webgoat.customjs.updateSpoofCookieForm = function () {
	var authenticated = $('#spoof_attack_output').text().trim().startsWith('Authenticated as ');
	$('#spoof_username, #spoof_password, #spoof_submit').prop('disabled', authenticated);
};

function cleanup(event) {
	event.preventDefault();
	$.ajax({
		url: $('#cleanup').attr('href'),
		method: 'GET'
	}).done(function () {
		$('#spoof_username, #spoof_password, #spoof_submit').prop('disabled', false);
		$('#spoof_attack_feedback, #spoof_attack_output').empty();
	}).fail(function () {
		$('#spoof_attack_feedback').text('Unable to delete the authentication cookie.').show();
	});
}
