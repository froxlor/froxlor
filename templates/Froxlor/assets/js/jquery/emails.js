export default function () {
	$(function () {

		/**
		 * bypass spam - hide unnecessary/unused sections
		 */
		if ($('#id') && $('#bypass_spam').is(':checked')) {
			$('#spam_tag_level').closest('.row').addClass('d-none');
			$('#spam_rewrite_subject').closest('.row').addClass('d-none');
			$('#spam_kill_level').closest('.row').addClass('d-none');
			$('#policy_greylist').closest('.row').addClass('d-none');
		}

		/**
		 * toggle show/hide of sections in case of bypass spam flag
		 */
		$('#bypass_spam').on('click', function () {
			if ($(this).is(':checked')) {
				// hide unnecessary sections
				$('#spam_tag_level').closest('.row').addClass('d-none');
				$('#spam_rewrite_subject').closest('.row').addClass('d-none');
				$('#spam_kill_level').closest('.row').addClass('d-none');
				$('#policy_greylist').closest('.row').addClass('d-none');
			} else {
				// show sections
				$('#spam_tag_level').closest('.row').removeClass('d-none');
				$('#spam_rewrite_subject').closest('.row').removeClass('d-none');
				$('#spam_kill_level').closest('.row').removeClass('d-none');
				$('#policy_greylist').closest('.row').removeClass('d-none');
			}
		})
	});
}
