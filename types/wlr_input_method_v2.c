#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <wayland-util.h>
#include <wlr/types/wlr_input_method_v2.h>
#include <wlr/types/wlr_surface.h>
#include <wlr/util/log.h>
#include <xkbcommon/xkbcommon.h>
#include "input-method-unstable-v2-protocol.h"
#include "util/shm.h"
#include "util/signal.h"

static const struct zwp_input_method_v2_interface input_method_impl;
static const struct zwp_input_method_keyboard_grab_v2_interface keyboard_grab_impl;

static struct wlr_input_method_v2 *input_method_from_resource(
		struct wl_resource *resource) {
	assert(wl_resource_instance_of(resource,
		&zwp_input_method_v2_interface, &input_method_impl));
	return wl_resource_get_user_data(resource);
}

static struct wlr_input_method_keyboard_grab_v2 *keyboard_grab_from_resource(
		struct wl_resource *resource) {
	assert(wl_resource_instance_of(resource,
		&zwp_input_method_keyboard_grab_v2_interface,
		&keyboard_grab_impl));
	return wl_resource_get_user_data(resource);
}

static void input_method_destroy(struct wlr_input_method_v2 *input_method) {
	wlr_signal_emit_safe(&input_method->events.destroy, input_method);
	wl_list_remove(wl_resource_get_link(input_method->resource));
	wl_list_remove(&input_method->seat_client_destroy.link);
	wlr_input_method_keyboard_grab_v2_destroy(input_method->keyboard_grab);
	free(input_method->pending.commit_text);
	free(input_method->pending.preedit.text);
	free(input_method->current.commit_text);
	free(input_method->current.preedit.text);
	free(input_method);
}

static void input_method_resource_destroy(struct wl_resource *resource) {
	struct wlr_input_method_v2 *input_method =
		input_method_from_resource(resource);
	if (!input_method) {
		return;
	}
	input_method_destroy(input_method);
}

static void im_destroy(struct wl_client *client, struct wl_resource *resource) {
	wl_resource_destroy(resource);
}

static void im_commit(struct wl_client *client, struct wl_resource *resource,
		uint32_t serial) {
	struct wlr_input_method_v2 *input_method =
		input_method_from_resource(resource);
	if (!input_method) {
		return;
	}
	input_method->current = input_method->pending;
	input_method->current_serial = serial;
	struct wlr_input_method_v2_state default_state = {0};
	input_method->pending = default_state;
	wlr_signal_emit_safe(&input_method->events.commit, (void*)input_method);
}

static void im_commit_string(struct wl_client *client,
		struct wl_resource *resource, const char *text) {
	struct wlr_input_method_v2 *input_method =
		input_method_from_resource(resource);
	if (!input_method) {
		return;
	}
	free(input_method->pending.commit_text);
	input_method->pending.commit_text = strdup(text);
}

static void im_set_preedit_string(struct wl_client *client,
		struct wl_resource *resource, const char *text, int32_t cursor_begin,
		int32_t cursor_end) {
	struct wlr_input_method_v2 *input_method =
		input_method_from_resource(resource);
	if (!input_method) {
		return;
	}
	input_method->pending.preedit.cursor_begin = cursor_begin;
	input_method->pending.preedit.cursor_end = cursor_end;
	free(input_method->pending.preedit.text);
	input_method->pending.preedit.text = strdup(text);
}

static void im_delete_surrounding_text(struct wl_client *client,
		struct wl_resource *resource,
		uint32_t before_length, uint32_t after_length) {
	struct wlr_input_method_v2 *input_method =
		input_method_from_resource(resource);
	if (!input_method) {
		return;
	}
	input_method->pending.delete.before_length = before_length;
	input_method->pending.delete.after_length = after_length;
}

static void im_get_input_popup_surface(struct wl_client *client,
		struct wl_resource *resource, uint32_t id,
		struct wl_resource *surface) {
	wlr_log(WLR_INFO, "Stub: zwp_input_method_v2::get_input_popup_surface");
}

void wlr_input_method_keyboard_grab_v2_destroy(
		struct wlr_input_method_keyboard_grab_v2 *keyboard_grab) {
	if (!keyboard_grab) {
		return;
	}
	wlr_signal_emit_safe(&keyboard_grab->events.destroy, keyboard_grab);
	keyboard_grab->input_method->keyboard_grab = NULL;
	if (keyboard_grab->keyboard) {
		wl_list_remove(&keyboard_grab->keyboard_keymap.link);
		wl_list_remove(&keyboard_grab->keyboard_repeat_info.link);
		wl_list_remove(&keyboard_grab->keyboard_destroy.link);
	}
	wl_resource_set_user_data(keyboard_grab->resource, NULL);
	free(keyboard_grab);
}

static void keyboard_grab_resource_destroy(struct wl_resource *resource) {
	struct wlr_input_method_keyboard_grab_v2 *keyboard_grab =
		keyboard_grab_from_resource(resource);
	wlr_input_method_keyboard_grab_v2_destroy(keyboard_grab);
}

static void keyboard_grab_release(struct wl_client *client,
		struct wl_resource *resource) {
	wl_resource_destroy(resource);
}

struct grab_state {
	uint32_t state;
	struct wl_array ranges;
	struct wl_array singles;
	struct wl_list link;
};

static void keyboard_configure_grab(struct wl_client *client,
			       struct wl_resource *resource,
			       uint32_t state,
			       struct wl_array *ranges,
			       struct wl_array *singles) {
	struct wlr_input_method_keyboard_grab_v2 *keyboard_grab =
		keyboard_grab_from_resource(resource);
	struct grab_state *grab_state = malloc(sizeof(*grab_state));
	grab_state->state = state;
	wl_array_init(&grab_state->ranges);
	wl_array_copy(&grab_state->ranges, ranges);
	wl_array_init(&grab_state->singles);
	wl_array_copy(&grab_state->singles, singles);
//	grab_state->ranges = ranges; // maybe copy here
//	grab_state->singles = singles;
	wl_list_insert(&keyboard_grab->grab_states, &grab_state->link);
}

struct grab_transition {
	uint32_t state_i;
	uint32_t state_f;
	struct wl_array singles;
	struct wl_list link;
};

static void keyboard_configure_transitions(struct wl_client *client,
				      struct wl_resource *resource,
				      uint32_t state_i,
				      uint32_t state_f,
				      struct wl_array *singles) {
	struct wlr_input_method_keyboard_grab_v2 *keyboard_grab =
		keyboard_grab_from_resource(resource);
	wlr_log(WLR_ERROR, "xyzzy size %ld", singles->size);
	struct grab_transition *tr = malloc(sizeof(*tr));
	tr->state_i = state_i;
	tr->state_f = state_f;
//	tr->singles = singles;
	wl_array_init(&tr->singles);
	wl_array_copy(&tr->singles, singles);
	wl_list_insert(&keyboard_grab->grab_transitions, &tr->link);
}

static const struct zwp_input_method_keyboard_grab_v2_interface keyboard_grab_impl = {
	.release = keyboard_grab_release,
	.configure_grab = keyboard_configure_grab,
	.configure_transitions = keyboard_configure_transitions,
};

static bool keyboard_grab_match(struct wlr_input_method_keyboard_grab_v2 *keyboard_grab, uint32_t key) {
	struct grab_state *grab_state;
	wl_list_for_each(grab_state, &keyboard_grab->grab_states, link) {
		if (grab_state->state != keyboard_grab->state)
    			continue;
		uint32_t *pos;
		struct wl_array *array = &grab_state->ranges;
//		wlr_log(WLR_ERROR, "xyzzy size %ld", array->size);
		for (pos = (array)->data;					
	     (const char *) pos < ((const char *) (array)->data + (array)->size);
	     (pos)+=2) {
//	wlr_log(WLR_ERROR, "xyzzy range from %x to %x", *pos, *(pos+1));
			if (key >= *pos && key <= *(pos+1))
    				return true;
		}
	}
	return false;
}

static void keyboard_grab_transition(struct wlr_input_method_keyboard_grab_v2 *keyboard_grab, uint32_t key) {
	struct grab_transition *grab_transition;
	wl_list_for_each(grab_transition, &keyboard_grab->grab_transitions, link) {
		if (grab_transition->state_i != keyboard_grab->state)
    			continue;
		uint32_t *pos;
		struct wl_array *array = &grab_transition->singles;
		for (pos = (array)->data;					
	     (const char *) pos < ((const char *) (array)->data + (array)->size);
	     (pos)+=2) {
			if (key >= *pos && key <= *(pos+1))
    				keyboard_grab->state = grab_transition->state_f;
		}
	}
}

static bool modactive(struct xkb_state *xkb_state) {
	return xkb_state_mod_names_are_active(xkb_state, XKB_STATE_MODS_EFFECTIVE, XKB_STATE_MATCH_ANY, XKB_MOD_NAME_CTRL, XKB_MOD_NAME_LOGO, XKB_MOD_NAME_CAPS, NULL) > 0;
}

void wlr_input_method_keyboard_grab_v2_send_key(
		struct wlr_input_method_keyboard_grab_v2 *keyboard_grab,
		uint32_t time, uint32_t key, uint32_t state) {
    		uint32_t keysym = xkb_state_key_get_one_sym(keyboard_grab->keyboard->xkb_state, key+8);
    		if (!modactive(keyboard_grab->keyboard->xkb_state) && keyboard_grab_match(keyboard_grab, keysym)) {
	zwp_input_method_keyboard_grab_v2_send_key(
		keyboard_grab->resource,
		wlr_seat_client_next_serial(keyboard_grab->input_method->seat_client),
		time, key, state);
		wlr_log(WLR_ERROR, "IM key %x", keysym);
		} else {
    		// passthrough
    		wlr_seat_keyboard_send_key(keyboard_grab->input_method->seat_client->seat, time, key, state);
		wlr_log(WLR_ERROR, "forward key %x", keysym);
		}
		if (state == WL_KEYBOARD_KEY_STATE_RELEASED)
			keyboard_grab_transition(keyboard_grab, keysym);
}

void wlr_input_method_keyboard_grab_v2_send_modifiers(
		struct wlr_input_method_keyboard_grab_v2 *keyboard_grab,
		struct wlr_keyboard_modifiers *modifiers) {
	zwp_input_method_keyboard_grab_v2_send_modifiers(
		keyboard_grab->resource,
		wlr_seat_client_next_serial(keyboard_grab->input_method->seat_client),
		modifiers->depressed, modifiers->latched,
		modifiers->locked, modifiers->group);

    		wlr_seat_keyboard_send_modifiers(keyboard_grab->input_method->seat_client->seat, modifiers);
}

static bool keyboard_grab_send_keymap(
		struct wlr_input_method_keyboard_grab_v2 *keyboard_grab,
		struct wlr_keyboard *keyboard) {
	int keymap_fd = allocate_shm_file(keyboard->keymap_size);
	if (keymap_fd < 0) {
		wlr_log(WLR_ERROR, "creating a keymap file for %zu bytes failed",
			keyboard->keymap_size);
		return false;
	}

	void *ptr = mmap(NULL, keyboard->keymap_size, PROT_READ | PROT_WRITE,
		MAP_SHARED, keymap_fd, 0);
	if (ptr == MAP_FAILED) {
		wlr_log(WLR_ERROR, "failed to mmap() %zu bytes",
			keyboard->keymap_size);
		close(keymap_fd);
		return false;
	}

	memcpy(ptr, keyboard->keymap_string, keyboard->keymap_size);
	munmap(ptr, keyboard->keymap_size);

	zwp_input_method_keyboard_grab_v2_send_keymap(keyboard_grab->resource,
		WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1, keymap_fd,
		keyboard->keymap_size);

	close(keymap_fd);
	return true;
}

static void keyboard_grab_send_repeat_info(
		struct wlr_input_method_keyboard_grab_v2 *keyboard_grab,
		struct wlr_keyboard *keyboard) {
	zwp_input_method_keyboard_grab_v2_send_repeat_info(
		keyboard_grab->resource, keyboard->repeat_info.rate,
		keyboard->repeat_info.delay);
}

static void handle_keyboard_keymap(struct wl_listener *listener, void *data) {
	struct wlr_input_method_keyboard_grab_v2 *keyboard_grab =
		wl_container_of(listener, keyboard_grab, keyboard_keymap);
	keyboard_grab_send_keymap(keyboard_grab, data);
}

static void handle_keyboard_repeat_info(struct wl_listener *listener,
		void *data) {
	struct wlr_input_method_keyboard_grab_v2 *keyboard_grab =
		wl_container_of(listener, keyboard_grab, keyboard_repeat_info);
	keyboard_grab_send_repeat_info(keyboard_grab, data);
}

static void handle_keyboard_destroy(struct wl_listener *listener,
		void *data) {
	struct wlr_input_method_keyboard_grab_v2 *keyboard_grab =
		wl_container_of(listener, keyboard_grab, keyboard_destroy);
	wlr_input_method_keyboard_grab_v2_set_keyboard(keyboard_grab, NULL);
}

void wlr_input_method_keyboard_grab_v2_set_keyboard(
		struct wlr_input_method_keyboard_grab_v2 *keyboard_grab,
		struct wlr_keyboard *keyboard) {
	if (keyboard == keyboard_grab->keyboard) {
		return;
	}

	if (keyboard_grab->keyboard) {
		wl_list_remove(&keyboard_grab->keyboard_keymap.link);
		wl_list_remove(&keyboard_grab->keyboard_repeat_info.link);
		wl_list_remove(&keyboard_grab->keyboard_destroy.link);
	}

	if (keyboard) {
		if (keyboard_grab->keyboard == NULL ||
				strcmp(keyboard_grab->keyboard->keymap_string,
				keyboard->keymap_string) != 0) {
			// send keymap only if it is changed, or if input method is not
			// aware that it did not change and blindly send it back with
			// virtual keyboard, it may cause an infinite recursion.
			if (!keyboard_grab_send_keymap(keyboard_grab, keyboard)) {
				wlr_log(WLR_ERROR, "Failed to send keymap for input-method keyboard grab");
				return;
			}
		}
		keyboard_grab_send_repeat_info(keyboard_grab, keyboard);
		keyboard_grab->keyboard_keymap.notify = handle_keyboard_keymap;
		wl_signal_add(&keyboard->events.keymap,
			&keyboard_grab->keyboard_keymap);
		keyboard_grab->keyboard_repeat_info.notify =
			handle_keyboard_repeat_info;
		wl_signal_add(&keyboard->events.repeat_info,
			&keyboard_grab->keyboard_repeat_info);
		keyboard_grab->keyboard_destroy.notify =
			handle_keyboard_destroy;
		wl_signal_add(&keyboard->events.destroy,
			&keyboard_grab->keyboard_destroy);

		wlr_input_method_keyboard_grab_v2_send_modifiers(keyboard_grab,
			&keyboard->modifiers);
	}

	keyboard_grab->keyboard = keyboard;
};

static void im_grab_keyboard(struct wl_client *client,
		struct wl_resource *resource, uint32_t keyboard) {
	struct wlr_input_method_v2 *input_method =
		input_method_from_resource(resource);
	if (!input_method) {
		return;
	}
	if (input_method->keyboard_grab) {
		// Already grabbed
		return;
	}
	struct wlr_input_method_keyboard_grab_v2 *keyboard_grab =
		calloc(1, sizeof(struct wlr_input_method_keyboard_grab_v2));
	wl_list_init(&keyboard_grab->grab_states);
	wl_list_init(&keyboard_grab->grab_transitions);
	if (!keyboard_grab) {
		wl_client_post_no_memory(client);
		return;
	}
	struct wl_resource *keyboard_grab_resource = wl_resource_create(
		client, &zwp_input_method_keyboard_grab_v2_interface,
		wl_resource_get_version(resource), keyboard);
	if (keyboard_grab_resource == NULL) {
		free(keyboard_grab);
		wl_client_post_no_memory(client);
		return;
	}
	wl_resource_set_implementation(keyboard_grab_resource,
		&keyboard_grab_impl, keyboard_grab,
		keyboard_grab_resource_destroy);
	keyboard_grab->resource = keyboard_grab_resource;
	keyboard_grab->input_method = input_method;
	input_method->keyboard_grab = keyboard_grab;
	wl_signal_init(&keyboard_grab->events.destroy);
	wlr_signal_emit_safe(&input_method->events.grab_keyboard, keyboard_grab);
}

static const struct zwp_input_method_v2_interface input_method_impl = {
	.destroy = im_destroy,
	.commit = im_commit,
	.commit_string = im_commit_string,
	.set_preedit_string = im_set_preedit_string,
	.delete_surrounding_text = im_delete_surrounding_text,
	.get_input_popup_surface = im_get_input_popup_surface,
	.grab_keyboard = im_grab_keyboard,
};

void wlr_input_method_v2_send_activate(
		struct wlr_input_method_v2 *input_method) {
	zwp_input_method_v2_send_activate(input_method->resource);
	input_method->active = true;
}

void wlr_input_method_v2_send_deactivate(
		struct wlr_input_method_v2 *input_method) {
	zwp_input_method_v2_send_deactivate(input_method->resource);
	input_method->active = false;
}

void wlr_input_method_v2_send_surrounding_text(
		struct wlr_input_method_v2 *input_method, const char *text,
		uint32_t cursor, uint32_t anchor) {
	const char *send_text = text;
	if (!send_text) {
		send_text = "";
	}
	zwp_input_method_v2_send_surrounding_text(input_method->resource, send_text,
		cursor, anchor);
}

void wlr_input_method_v2_send_text_change_cause(
		struct wlr_input_method_v2 *input_method, uint32_t cause) {
	zwp_input_method_v2_send_text_change_cause(input_method->resource, cause);
}

void wlr_input_method_v2_send_content_type(
		struct wlr_input_method_v2 *input_method,
		uint32_t hint, uint32_t purpose) {
	zwp_input_method_v2_send_content_type(input_method->resource, hint,
		purpose);
}

void wlr_input_method_v2_send_done(struct wlr_input_method_v2 *input_method) {
	zwp_input_method_v2_send_done(input_method->resource);
	input_method->client_active = input_method->active;
	input_method->current_serial++;
}

void wlr_input_method_v2_send_unavailable(
		struct wlr_input_method_v2 *input_method) {
	zwp_input_method_v2_send_unavailable(input_method->resource);
	struct wl_resource *resource = input_method->resource;
	input_method_destroy(input_method);
	wl_resource_set_user_data(resource, NULL);
}

static const struct zwp_input_method_manager_v2_interface
	input_method_manager_impl;

static struct wlr_input_method_manager_v2 *input_method_manager_from_resource(
		struct wl_resource *resource) {
	assert(wl_resource_instance_of(resource,
		&zwp_input_method_manager_v2_interface, &input_method_manager_impl));
	return wl_resource_get_user_data(resource);
}

static void input_method_handle_seat_client_destroy(struct wl_listener *listener,
		void *data) {
	struct wlr_input_method_v2 *input_method = wl_container_of(listener,
		input_method, seat_client_destroy);
	wlr_input_method_v2_send_unavailable(input_method);
}

static void manager_get_input_method(struct wl_client *client,
		struct wl_resource *resource, struct wl_resource *seat,
		uint32_t input_method_id) {
	struct wlr_input_method_manager_v2 *im_manager =
		input_method_manager_from_resource(resource);

	struct wlr_input_method_v2 *input_method = calloc(1,
		sizeof(struct wlr_input_method_v2));
	if (!input_method) {
		wl_client_post_no_memory(client);
		return;
	}
	wl_signal_init(&input_method->events.commit);
	wl_signal_init(&input_method->events.grab_keyboard);
	wl_signal_init(&input_method->events.destroy);
	int version = wl_resource_get_version(resource);
	struct wl_resource *im_resource = wl_resource_create(client,
		&zwp_input_method_v2_interface, version, input_method_id);
	if (im_resource == NULL) {
		free(input_method);
		wl_client_post_no_memory(client);
		return;
	}
	wl_resource_set_implementation(im_resource, &input_method_impl,
		input_method, input_method_resource_destroy);

	input_method->seat_client = wlr_seat_client_from_resource(seat);
	input_method->seat = input_method->seat_client->seat;
	wl_signal_add(&input_method->seat_client->events.destroy,
		&input_method->seat_client_destroy);
	input_method->seat_client_destroy.notify =
		input_method_handle_seat_client_destroy;

	input_method->resource = im_resource;
	wl_list_insert(&im_manager->input_methods,
		wl_resource_get_link(input_method->resource));
	wlr_signal_emit_safe(&im_manager->events.input_method, input_method);
}

static void manager_destroy(struct wl_client *client,
		struct wl_resource *resource) {
	wl_resource_destroy(resource);
}

static const struct zwp_input_method_manager_v2_interface
		input_method_manager_impl = {
	.get_input_method = manager_get_input_method,
	.destroy = manager_destroy,
};

static void input_method_manager_bind(struct wl_client *wl_client, void *data,
		uint32_t version, uint32_t id) {
	assert(wl_client);
	struct wlr_input_method_manager_v2 *im_manager = data;

	struct wl_resource *bound_resource = wl_resource_create(wl_client,
		&zwp_input_method_manager_v2_interface, version, id);
	if (bound_resource == NULL) {
		wl_client_post_no_memory(wl_client);
		return;
	}
	wl_resource_set_implementation(bound_resource, &input_method_manager_impl,
		im_manager, NULL);
}

static void handle_display_destroy(struct wl_listener *listener, void *data) {
	struct wlr_input_method_manager_v2 *manager =
		wl_container_of(listener, manager, display_destroy);
	wlr_signal_emit_safe(&manager->events.destroy, manager);
	wl_list_remove(&manager->display_destroy.link);
	wl_global_destroy(manager->global);
	free(manager);
}

struct wlr_input_method_manager_v2 *wlr_input_method_manager_v2_create(
		struct wl_display *display) {
	struct wlr_input_method_manager_v2 *im_manager = calloc(1,
		sizeof(struct wlr_input_method_manager_v2));
	if (!im_manager) {
		return NULL;
	}
	wl_signal_init(&im_manager->events.input_method);
	wl_signal_init(&im_manager->events.destroy);
	wl_list_init(&im_manager->input_methods);

	im_manager->global = wl_global_create(display,
		&zwp_input_method_manager_v2_interface, 2, im_manager,
		input_method_manager_bind);
	if (!im_manager->global) {
		free(im_manager);
		return NULL;
	}

	im_manager->display_destroy.notify = handle_display_destroy;
	wl_display_add_destroy_listener(display, &im_manager->display_destroy);

	return im_manager;
}
