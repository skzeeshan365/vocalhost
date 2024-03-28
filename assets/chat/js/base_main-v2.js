"use strict";

function load_chat_room(url) {
    history.replaceState(null, document.title, '/chat/');
    window.location.href = url;
}

// Section: Handle New Message
const STATUS_DELIVERED = 0;
const STATUS_SEEN = 1;
const STATUS_RECEIVED = 2;
const STATUS_RECEIVED_INITIAL = 3;
const STATUS_TYPING = 4;

function handleNewMessage(username, timestamp, background = true) {
    var personElement = document.querySelector(`[data-chat='${username}']`);

    if (personElement) {
        var previewElement = personElement.querySelector('.preview');

        if (background) {
            previewElement.style.color = "#ffffff";
        }

        var timeElement = personElement.querySelector('.time');
        if (timeElement) {
            timeElement.textContent = getFormattedTime(timestamp);
            if (background) {
                timeElement.style.color = "#ffffff";
            }
        }
        update_user_list(username);

        if (background) {
            update_message_status(STATUS_RECEIVED_INITIAL, username);
        }
    }
}

function update_message_status(seen, username, previous = true) {
    var personElement = document.querySelector(`[data-chat='${username}']`);
    if (personElement) {
        var previewElement = personElement.querySelector('.preview');
        if (previewElement) {
            var textSpan = document.createElement('span');
            var icon = previewElement.querySelector('.status_icon');
            if (icon) {
                if (seen === STATUS_DELIVERED) {
                    icon.src = icon_delivered
                    textSpan.textContent = 'Delivered';
                } else if (seen === STATUS_SEEN) {
                    icon.src = icon_seen
                    textSpan.textContent = 'Opened';
                } else if (seen === STATUS_RECEIVED) {
                    icon.src = icon_received
                    textSpan.textContent = 'Received';
                } else if (seen === STATUS_RECEIVED_INITIAL) {
                    icon.src = icon_received_fill
                    textSpan.textContent = 'Received';
                } else if (seen === STATUS_TYPING) {
                    icon.src = icon_received
                    textSpan.textContent = 'Typing...';
                }
                icon = document.getElementById('status_icon').cloneNode(true);
                previewElement.innerHTML = '';
                previewElement.appendChild(icon);
                previewElement.appendChild(textSpan);
                if (previous) {
                    personElement.setAttribute('message_status', seen.toString())
                }
            } else {
                console.log('Icon element not found inside preview');
            }
        } else {
            console.log('preview null');
        }
    } else {
        console.log('person null');
    }
}

function update_user_list(username) {
    const personElement = document.querySelector(`[data-chat="${username}"]`);

    if (personElement) {
        const parentElement = personElement.parentNode;
        const firstChild = parentElement.firstChild;

        if (firstChild !== personElement) {
            parentElement.insertBefore(personElement, firstChild);
        }
    }
}

// handle new message

// Section: Core message
let chatSocket = null;

async function get_user_private_keys_secondary() {
    $.ajax({
        type: 'POST',
        url: `/chat/get/private-keys/secondary/`,
        dataType: 'json',
        success: async function (response) {
            if (response.status === 'success') {
                saveSecondaryKey(response.private_key.key, response.private_key.token);
                generate_room_private_keys();
            } else {
                console.error('Error loading messages:', response.error);
            }
        },
        error: function (error) {
            console.error('Error loading messages:', error);
        }
    });
}

function getUsernameByRoom(room) {
    var userElements = document.querySelectorAll('.person[data-room="' + room + '"]');
    if (userElements.length > 0) {
        return userElements[0].getAttribute('data-chat');
    } else {
        return null;
    }
}

function getRoomByUsername(username) {
    var userElement = document.querySelector('.person[data-chat="' + username + '"]');
    if (userElement) {
        return userElement.getAttribute('data-room');
    } else {
        return null;
    }
}

document.addEventListener('DOMContentLoaded', function () {
    initialize_socket();
    if (!getSecondaryKey()) {
        (async () => {
            await get_user_private_keys_secondary();
        })();
    } else {
        if (key) {
            saveSecondaryKey(key.private_key, key.token);
        }
        generate_room_private_keys();
    }

    let text = document.getElementById('feature_message');
    if (text) {
        text.textContent = display_feature_message();
    }
});

function insert_new_user(username, room, fullname, timestamp, img_src) {
    var userList = document.querySelector('.people');

    var newListElement = document.createElement('li');
    newListElement.className = 'person context-menu-trigger';
    newListElement.setAttribute('data-chat', username);
    newListElement.setAttribute('data-room', room)
    newListElement.onclick = function () {
        window.location.href = `/chat/${room}`;
    };
    newListElement.innerHTML = `
            <!-- Add your default values here -->
            <img class="users_profile_pic" src="${img_src}" alt="Profile picture"/>
            <span class="name">${fullname}</span>
            <span class="time">${timestamp}</span>
            <span class="preview">
                <img class="status_icon" id="status_icon" style="margin-right: 5px; height: 25px; width: 25px;" src="${icon_received}" alt="Icon">
                Tap to chat
            </span>
            <!-- End default values -->
        `;
    newListElement.setAttribute('data-timestamp', timestamp);  // Set default timestamp to empty string

    userList.insertBefore(newListElement, userList.firstChild);
}

function remove_user(username) {
    let personElement = document.querySelector(`[data-chat='${username}']`);
    if (personElement) {
        personElement.remove();
    }
}

function initialize_socket() {
    const web_socket_url = `${protocol}://` + window.location.host + `/ws/chat/`
    chatSocket = new WebSocket(web_socket_url);
    chatSocket.binaryType = 'blob'

    chatSocket.onopen = function (event) {
        console.log('WebSocket connection opened');
    };

    chatSocket.onclose = function (event) {
        if (event.code !== 1000) {
            console.log('Reconnecting...');
            setTimeout(initialize_socket, 10000);
        }
    };

    chatSocket.onerror = function (error) {
        console.error('WebSocket encountered an error:', error);
    };

    chatSocket.onmessage = async function (e) {
        if (e.data instanceof Blob) {
            //
        } else {
            const data = JSON.parse(e.data);
            if (data.type === 'new_message_background') {
                handleNewMessage(data.sender_username, data.timestamp);
            } else if (data.type === 'message_seen') {
                update_message_status(STATUS_SEEN, data.sender_username);
            } else if (data.type === 'message_status_background') {
                update_message_status(STATUS_SEEN, data.sender_username);
            } else if (data.type === 'typing_status') {
                console.log(data);
                update_typing_status(data.sender_username, data.typing);
            } else if (data.type === 'friend_request_accepted') {
                let img;
                let fullname;
                if (data.image_url) {
                    img = data.image_url
                } else {
                    img = default_user_icon
                }

                if (data.fullname !== '') {
                    fullname = data.fullname
                } else {
                    fullname = data.username
                }
                var currentTime = new Date();
                let timestamp = getFormattedTime(currentTime)
                insert_new_user(data.username, data.room, fullname, timestamp, img)
            } else if (data.type === 'remove_friend') {
                remove_user(data.username);
            }
        }
    }
}

function isWebSocketReady(socket) {
    if (socket) {
        if (socket.readyState === WebSocket.OPEN) {
            return true;
        }
    }
    return false;
}

function getFormattedTime(timestampOrDateString) {
    if (timestampOrDateString !== undefined && timestampOrDateString !== null) {
        const timestamp = Number(timestampOrDateString);

        if (!isNaN(timestamp)) {
            const date = new Date(timestamp);
            return date.toLocaleTimeString('en-US', {hour: 'numeric', minute: 'numeric', hour12: true});
        } else {
            // It's a date string
            return timestampOrDateString;
        }
    } else {
        return 'Invalid Date';
    }
}

// Section: User list context menu
const contextMenuTriggers = document.querySelectorAll('.context-menu-trigger');
let activeContextMenu = null;

function hideContextMenu_profile() {
    if (activeContextMenu) {
        activeContextMenu.style.display = 'none';
        document.removeEventListener('click', hideContextMenu);
        activeContextMenu = null;
    }
}

contextMenuTriggers.forEach(function (contextMenuTrigger) {
    contextMenuTrigger.addEventListener('contextmenu', function (event) {
        showContextMenuProfile(event, contextMenuTrigger);
    });
});

let trigger_global = null;

function showContextMenuProfile(event, trigger_local) {
    event.preventDefault();

    // Access the context menu directly
    const contextMenu = document.getElementById('contextMenu_profile');

    // Set the position of the context menu
    contextMenu.style.display = 'block';
    contextMenu.style.left = event.pageX + 'px';
    contextMenu.style.top = event.pageY + 'px';

    // Hide any active context menu
    hideContextMenu_profile();

    if (trigger_local) {
        trigger_global = trigger_local;
    }

    // Set the active context menu
    activeContextMenu = contextMenu;

    // Attach a click event listener to the document to hide the context menu when clicking outside
    document.addEventListener('click', hideContextMenu_profile);
}

function handleContextMenu_profile(option) {
    if (option === 'clear_chat') {
        const username = trigger_global.getAttribute('data-chat');
        clear_chat(username);
    } else if (option === 'remove') {
        const username = trigger_global.getAttribute('data-chat');
        remove_chat(username);
    } else if (option === 'about') {
        const username = trigger_global.getAttribute('data-chat');
        if (username) {
            window.location.href = `/chat/profile/${username}`;
        }
    }
}

function clear_chat(username) {
    $.ajax({
        type: 'POST',
        url: '/chat/clear/chat/',
        data: JSON.stringify({
            'username': username
        }),
        contentType: 'application/json',
        success: function (data) {
            if (data.success) {
                var previewElement = trigger_global.querySelector('.preview');
                var timeElement = trigger_global.querySelector('.time');
                previewElement.textContent = 'Tap to chat';
                timeElement.textContent = '';
            } else {
                console.log(data.error)
            }
        },
        error: function (xhr, status, error) {
            console.error(error);
        }
    });
}

function remove_chat(username) {
    $.ajax({
        type: 'POST',
        url: '/chat/remove/chat/',
        data: JSON.stringify({
            'username': username
        }),
        contentType: 'application/json',
        success: function (data) {
            if (data.success) {
                trigger_global.remove();
                if (isWebSocketReady()) {
                    chatSocket.send(JSON.stringify({
                        'type': 'initialize_receiver',
                        'receiver_username': null,
                    }));
                }
            } else {
                console.log(data.error)
            }
        },
        error: function (xhr, status, error) {
            console.error(error);
        }
    });
}

// User list context menu

// Section: Typing
function update_typing_status(username, typing) {

    var personElement = document.querySelector(`[data-chat='${username}']`);

    if (typing) {
        update_message_status(STATUS_TYPING, username, false);
    } else {
        if (personElement) {
            var statusValue = personElement.getAttribute('message_status');
            if (statusValue) {
                var intValue = parseInt(statusValue, 10);
                update_message_status(intValue, username, false);
            } else {
                update_message_status(STATUS_RECEIVED, username, false);
            }
        }
    }
}

// Section: RetrieveKeys
function base64StringToArrayBuffer(base64) {
    let binaryString = window.atob(base64);
    let len = binaryString.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

function base64StringToUint8Array(base64) {
    let binaryString = window.atob(base64);
    let length = binaryString.length;

    let bytes = new Uint8Array(length);

    for (let i = 0; i < length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }

    return bytes;
}

function display_feature_message() {
    var randomMessages = [
        "Your messages are super secure with end-to-end encryption, keeping your chats private.",
        "Chat seamlessly on any device. Each operates independently, so you can log in and start chatting from anywhere.",
        "No need to worry about connecting devices. Each one operates independently!",
        "New devices joining the chat won't access past messages, ensuring privacy and security.",
        "Exciting updates coming soon to enhance your chatting experience even more!"
    ];

    var randomIndex = Math.floor(Math.random() * randomMessages.length);

    // Return the randomly selected message
    return randomMessages[randomIndex];
}

function generate_room_private_keys() {
    var userListItems = document.querySelectorAll('.people .person');

    // Iterate over each list item
    userListItems.forEach(function (userListItem) {
        let username = userListItem.getAttribute('data-chat');
        var room = userListItem.getAttribute('data-room');
        let roomData = getKeysByRoom(room);
        if (!roomData || !roomData.private_keys || !roomData.version) {
            $.ajax({
                type: 'POST',
                url: '/chat/get/private-keys/ratchet/',
                dataType: 'json',
                data: JSON.stringify({
                    receiver_username: username,
                }),
                success: function (response) {
                    if (response.status === 'success') {
                        if (response.private_keys.type === 0) {
                            saveKeys_sender(response.room, response.private_keys.version, response.private_keys.ik_private_key, response.private_keys.ek_private_key, response.private_keys.dhratchet_private_key);
                        } else if (response.private_keys.type === 1) {
                            saveKeys_receiver(response.room, response.private_keys.version, response.private_keys.ik_private_key, response.private_keys.spk_private_key, response.private_keys.opk_private_key, response.private_keys.dhratchet_private_key)
                        }
                    } else {
                        console.error('Error:', response.error);
                    }
                },
                error: function (error) {
                    console.error('Error:', error);
                }
            });
        }

    });
}