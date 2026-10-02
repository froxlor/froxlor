export default function () {
	$(function () {
		/*
		 * table columns - manage columns modal
		 */
		$('.manageColumnsModal form').on('submit', function (event) {
			$.ajax({
				url: 'lib/ajax.php?action=updatetablelisting&listing=' + $(this).data('listing') + '&theme=' + window.$theme,
				type: 'POST',
				dataType: 'json',
				beforeSend: function(request) {
					request.setRequestHeader(
						'X-CSRF-TOKEN',
						document.querySelector('meta[name="csrf-token"]').getAttribute('content')
					);
				},
				data: $(this).serialize(),
				success: function () {
					window.location.href = '';
				},
				error: function (request) {
					alert(request.responseJSON.message);
				}
			});
			event.preventDefault();
		});

		$('.manageColumnsModal form button[data-action="reset"]').on('click', function () {
			var form = $(this).parents('form:first');
			$.ajax({
				url: 'lib/ajax.php?action=resettablelisting&listing=' + form.data('listing') + '&theme=' + window.$theme,
				type: 'POST',
				dataType: 'json',
				beforeSend: function(request) {
					request.setRequestHeader(
						'X-CSRF-TOKEN',
						document.querySelector('meta[name="csrf-token"]').getAttribute('content')
					);
				},
				data: {},
				success: function () {
					window.location.href = '';
				},
				error: function (request) {
					alert(request.responseJSON.message);
				}
			});
		});

		$('.manageColumnsModal form button[data-action="select-all"]').on('click', function () {
			$(this).parents('form:first').find('input:checkbox').prop('checked', true);
		});

		$('.manageColumnsModal form button[data-action="unselect-all"]').on('click', function () {
			$(this).parents('form:first').find('input:checkbox').prop('checked', false);
		});
	});
}
