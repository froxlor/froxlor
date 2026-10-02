export default function () {
	$(function () {
		var timer, delay = 650;
		$('div[data-action="apikeys"] #allowed_from').on('keyup change', function () {
			var _this = $(this);
			clearTimeout(timer);
			timer = setTimeout(function () {
				var akid = _this.closest('div[data-action="apikeys"]').data('entry');
				$.ajax({
					url: "lib/ajax.php?action=editapikey",
					type: "POST",
					dataType: "json",
					beforeSend: function (request) {
						request.setRequestHeader('X-CSRF-TOKEN', document.querySelector('meta[name="csrf-token"]').getAttribute('content'));
					},
					data: {
						id: akid,
						allowed_from: _this.val(),
						valid_until: $('div[data-entry="' + akid + '"] #valid_until').val()
					},
					success: function (data) {
						if (data.message) {
							_this.removeClass('is-valid');
							_this.addClass('is-invalid');
						} else {
							_this.removeClass('is-invalid');
							_this.addClass('is-valid');
							_this.val(data.allowed_from);
						}
					},
					error: function (request, status, error) {
						_this.removeClass('is-valid');
						_this.addClass('is-invalid');
					}
				});
			}, delay);
		});

		$('div[data-action="apikeys"] #valid_until').on('keyup change', function () {
			var _this = $(this);
			clearTimeout(timer);
			timer = setTimeout(function () {
				var akid = _this.closest('div[data-action="apikeys"]').data('entry');
				$.ajax({
					url: "lib/ajax.php?action=editapikey",
					type: "POST",
					dataType: "json",
					beforeSend: function (request) {
						request.setRequestHeader('X-CSRF-TOKEN', document.querySelector('meta[name="csrf-token"]').getAttribute('content'));
					},
					data: {
						id: akid,
						valid_until: _this.val(),
						allowed_from: $('div[data-entry="' + akid + '"] #allowed_from').val()
					},
					success: function (data) {
						if (data.message) {
							_this.removeClass('is-valid');
							_this.addClass('is-invalid');
						} else {
							_this.removeClass('is-invalid');
							_this.addClass('is-valid');
							//_this.val(data.valid_until);
						}
					},
					error: function (request, status, error) {
						_this.removeClass('is-valid');
						_this.addClass('is-invalid');
					}
				});
			}, delay);
		});
	});
}
