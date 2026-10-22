import '@fortawesome/fontawesome-free';
import './bootstrap';

// Note: Vue is intentionally NOT mounted on the page. It is not used by any template, and
// mounting it on <body> makes its runtime compiler evaluate every "{{ ... }}" found in the
// rendered HTML - including user controlled data like webserver logs, descriptions or
// domain names - as a Vue expression (client-side template injection / XSS).

// Load jquery components
Object.entries(import.meta.glob('./jquery/*.js', {eager: true})).forEach(([path, definition]) => {
	definition.default();
});
