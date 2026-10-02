export default function () {
	$(function () {
		/*
		 * domains
		 */
		// disable unusable php-configuration by customer settings
		$('#customerid').on('change', function () {
			var cid = $(this).val();
			$.ajax({
				url: "admin_domains.php?page=domains&action=jqGetCustomerPHPConfigs",
				type: "POST",
				data: {
					customerid: cid
				},
				dataType: "json",
				beforeSend: function (request) {
					request.setRequestHeader('X-CSRF-TOKEN', document.querySelector('meta[name="csrf-token"]').getAttribute('content'));
				},
				success: function (json) {
					if (json.length > 0) {
						$('#phpsettingid option').each(function () {
							var pid = $(this).val();
							$(this).attr("disabled", "disabled");
							for (var i in json) {
								if (pid == json[i]) {
									$(this).removeAttr("disabled");
								}
							}
						});
					}
				},
				error: function (a, b) {
					console.log(a, b);
				}
			});
		});

		// show warning if speciallogfile option is toggled
		if ($('input[name=speciallogverified]')) {
			$('input[name=speciallogfile]').on('click', function () {
				$('#speciallogfilenote').remove();
				$('#speciallogfile').removeClass('is-invalid');
				$('#speciallogverified').val(0);
				const cFileName = window.location.pathname.substring(window.location.pathname.lastIndexOf("/")+1);
				$.ajax({
					url: cFileName + "?page=overview&action=jqSpeciallogfileNote",
					type: "POST",
					data: {
						id: $('input[name=id]').val(), newval: +$('#speciallogfile').is(':checked')
					},
					dataType: "json",
					async: false,
					beforeSend: function (request) {
						request.setRequestHeader('X-CSRF-TOKEN', document.querySelector('meta[name="csrf-token"]').getAttribute('content'));
					},
					success: function (json) {
						if (json.changed) {
							$('#speciallogfile').addClass('is-invalid');
							$('#speciallogfile').parent().append(json.info);
							$('#speciallogverified').val(1);
						}
					},
					error: function (a, b) {
						console.log(a, b);
					}
				});
			});
		}

		// show warning if emaildomain option is set to disabled but was enabled
		if ($('input[name=emaildomainverified]')) {
			$('input[name=isemaildomain]').on('click', function () {
				$('#emaildomainnote').remove();
				$('#isemaildomain').removeClass('is-invalid');
				$('#emaildomainverified').val(0);
				const cFileName = window.location.pathname.substring(window.location.pathname.lastIndexOf("/")+1);
				$.ajax({
					url: cFileName + "?page=overview&action=jqEmaildomainNote",
					type: "POST",
					data: {
						id: $('input[name=id]').val(), newval: +$('#isemaildomain').is(':checked')
					},
					dataType: "json",
					async: false,
					beforeSend: function (request) {
						request.setRequestHeader('X-CSRF-TOKEN', document.querySelector('meta[name="csrf-token"]').getAttribute('content'));
					},
					success: function (json) {
						if (json.changed) {
							$('#isemaildomain').addClass('is-invalid');
							$('#isemaildomain').parent().append(json.info);
							$('#emaildomainverified').val(1);
						}
					},
					error: function (a, b) {
						console.log(a, b);
					}
				});
			});
		}

		/**
		 * email only domain - hide unnecessary/unused sections
		 */
		if ($('#id') && $('#email_only').is(':checked')) {
			$('#section_b').hide();
			$('#section_bssl').hide();
			$('#section_c').hide();
		}

		/**
		 * toggle show/hide of sections in case of email only flag
		 */
		$('#email_only').on('click', function () {
			if ($(this).is(':checked')) {
				// hide unnecessary sections
				$('#section_b').hide();
				$('#section_bssl').hide();
				$('#section_c').hide();
			} else {
				// show sections
				$('#section_b').show();
				$('#section_bssl').show();
				$('#section_c').show();
			}
		})

		/**
		 * ssl enabled domain - hide unnecessary/unused sections
		 */
		if ($('#id') && !$('#sslenabled').is(':checked')) {
			$('#section_bssl>.formfields>.row').not(":first").addClass("d-none");
		}

		/**
		 * toggle show/hide of sections in case of ssl enabled flag
		 */
		$('#sslenabled').on('click', function () {
			if ($(this).is(':checked')) {
				// show sections
				$('#section_bssl>.formfields>.row').removeClass("d-none");
			} else {
				// hide unnecessary sections
				$('#section_bssl>.formfields>.row').not(":first").addClass("d-none");
			}
		})
	});
}
