"use strict";

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
const chatContainer = document.getElementById('chat_container');
let chatSocket = null;

let bytes_webpBlob = null;
let bytes_message = null;
let sent_reply_id = null;

let encryption = null;
const encryption_instance = {};
const asymmetricInstances = {};
let asymmetric_private_instance = null;

function close_chat() {
    document.getElementById('chat_parent_container').style.display = 'none';
    document.getElementById('left_bar').style.display = 'block';
}

function close_all_chats() {
    var snapUiContainer = document.getElementById('snap-ui-container');
    while (snapUiContainer.firstChild) {
        snapUiContainer.removeChild(snapUiContainer.firstChild);
    }
    document.getElementById('container_image').style.display = 'flex';
    resetActiveness();
    var inputBoxContainer = document.getElementById('input-box-container');
    inputBoxContainer.style.display = 'none';
    var header_content = document.getElementById('header_content');
    header_content.style.display = 'none';
}

function preloaderStart() {
    var preloader = document.getElementById('preloader');
    preloader.style.display = 'flex';
}

function preloaderEnd() {
    setTimeout(function () {
        var preloader = document.getElementById('preloader');
        preloader.style.display = 'none';
    }, 1000); // Adjust the delay time as needed
}
function load_chat(userName) {
    preloaderStart();
    if (window.innerWidth <= 768) {
        document.getElementById('chat_parent_container').style.display = 'block';
        document.getElementById('left_bar').style.display = 'none';
    }
    document.getElementById('container_image').style.display = 'none';

    resetActiveness();
    var snapUiContainer = document.getElementById('snap-ui-container');

    while (snapUiContainer.firstChild) {
        snapUiContainer.removeChild(snapUiContainer.firstChild);
    }

    var inputBoxContainer = document.getElementById('input-box-container');
    inputBoxContainer.style.display = 'none';
    var header_content = document.getElementById('header_content');
    header_content.style.display = 'none';
    document.querySelector(`.person[data-chat=${userName}]`).classList.add('active')

    var personElement = document.querySelector(`[data-chat='${userName}']`);

    var previewElement = personElement.querySelector('.preview');
    previewElement.style.color = '#ababab';

    var timeElement = personElement.querySelector('.time');
    if (timeElement) {
        timeElement.style.color = '#8a8a8a';
    }

    var header_picture = document.getElementById('header_picture');
    let image_url = personElement.querySelector('.users_profile_pic');
    header_picture.src = image_url.src;

    if (userName) {
        chatSocket.send(JSON.stringify({
            'type': 'initialize_receiver',
            'receiver_username': userName,
        }));
    }
    let roomData = getKeysByRoom(getActiveRoom());
    let generate_keys = false;
    if (roomData && roomData.type && roomData) {
        generate_keys = false;
    } else {
        generate_keys = true;
    }

    $.ajax({
        type: 'POST',
        url: `/chat/load/messages/${userName}/`,
        dataType: 'json',
        data: JSON.stringify({
            generate_keys: generate_keys,
        }),
        success: function (response) {
            if (response.status === 'success') {
                var messages = JSON.parse(response.data);
                (async () => {
                    await load_chat_message(messages, response.keys.public_keys);
                    if (response.generate_keys) {
                    if (response.keys.private_keys.type === 0) {
                        saveKeys_sender(getActiveRoom(), response.keys.private_keys.version, response.keys.private_keys.ik_private_key, response.keys.private_keys.ek_private_key, response.keys.private_keys.dhratchet_private_key);
                    } else if (response.keys.private_keys.type === 1) {
                        saveKeys_receiver(getActiveRoom(), response.keys.private_keys.version, response.keys.private_keys.ik_private_key, response.keys.private_keys.spk_private_key, response.keys.private_keys.opk_private_key, response.keys.private_keys.dhratchet_private_key)
                    }
                }
                    await initialize_keys(getActiveRoom(), response.keys.public_keys);
                })();
            } else {
                console.error('Error loading messages:', response.message);
            }
        },
        error: function (error) {
            console.error('Error loading messages:', error);
            preloaderEnd();
        }
    });


    header_content.addEventListener('click', function (event) {
        window.location.href = `/chat/profile/${userName}`;
    });
}

async function load_chat_message(messages, public_keys) {
    const snapUiContainer = document.getElementById('snap-ui-container');
    snapUiContainer.addEventListener('mouseover', handleHover);
    snapUiContainer.addEventListener('mouseout', handleHoverEnd);

    // Group messages by date
    const messagesByDate = groupMessagesByDate(messages);

    // Check if there are no messages at all
    if (Object.keys(messagesByDate).length === 0) {
        const currentDate = new Date();
        const formattedDate = currentDate.toISOString().split('T')[0];
        addSnapNotice(formattedDate);
    }

    let newMessage = true;

    // Loop through the grouped messages and append them to the chat container
    for (const [date, messagesInDate] of Object.entries(messagesByDate)) {
        let dateAppended = false;  // Flag to track whether the date has been appended

        const messagesForDate = messagesInDate.sort((a, b) => a.message_id - b.message_id);

        for (const [index, message] of messagesForDate.entries()) {
            // Determine if the message is sent or received based on the sender
            const messageType = message.sender__username === userUsername ? 'you' : getActivePerson();

            if (index === 0 && !dateAppended) {
                // Append the date
                addSnapNotice(date);
                dateAppended = true;
            }

            const save = message.saved;
            let text_message;
            let image_url;
            if (message.child_message) {
                let encryption = null;
                if (message.child_message.base_public_key) {
                    encryption = await initialize_ratchet_encryption_temp(getActiveRoom(), message.child_message.base_public_key, message.child_message.public_key, message.child_message.device_id);
                }
                if (encryption) {
                    if (message.child_message.public_key) {
                        await encryption.setReceiverKey(message.child_message.public_key);
                        if (message.child_message.bytes_cipher) {
                            if (message.child_message.cipher) {
                                let decrypted_cipher = await encryption.recvImage(base64StringToUint8Array(message.child_message.bytes_cipher), base64StringToArrayBuffer(message.child_message.cipher));
                                if (decrypted_cipher) {
                                    const imageBlob = new Blob([decrypted_cipher.image_bytes], {type: 'image/webp'});
                                    text_message = decrypted_cipher.text_message;
                                    image_url = URL.createObjectURL(imageBlob);
                                } else {
                                    text_message = message.message || null;
                                    image_url = message.image_url || null;
                                }
                            } else {
                                let decrypted_cipher = await encryption.recvImage(base64StringToUint8Array(message.child_message.bytes_cipher), null);
                                if (decrypted_cipher) {
                                    const imageBlob = new Blob([decrypted_cipher.image_bytes], {type: 'image/webp'});
                                    image_url = URL.createObjectURL(imageBlob);
                                    text_message = message.message || null;
                                } else {
                                    text_message = message.message || null;
                                    image_url = message.image_url || null;
                                }
                            }
                        } else if (message.child_message.cipher) {
                            text_message = await encryption.recv(base64StringToArrayBuffer(message.child_message.cipher));
                            image_url = message.image_url || null;
                        } else {
                            await encryption.recv(null);
                            text_message = message.message || null;
                            image_url = message.image_url || null;
                        }
                    } else {
                        text_message = message.message || null;
                        image_url = message.image_url || null;
                    }
                } else {
                    text_message = message.message || null;
                    image_url = message.image_url || null;
                }
            } else if (message.sent_message) {
                if (message.sent_message.cipher_bytes) {
                    let decrypted_cipher = await asymmetric_private_instance.decrypt_Image_Message(base64StringToUint8Array(message.sent_message.cipher_bytes), base64StringToArrayBuffer(message.sent_message.cipher), base64StringToArrayBuffer(message.sent_message.AES));
                    if (decrypted_cipher) {
                        const imageBlob = new Blob([decrypted_cipher.cipher_bytes], {type: 'image/webp'});
                        image_url = URL.createObjectURL(imageBlob);
                        text_message = decrypted_cipher.text_message;
                    } else {
                        text_message = message.message || null;
                        image_url = message.image_url || null;
                    }
                } else {
                    text_message = await asymmetric_private_instance.decryptMessage(base64StringToArrayBuffer(message.sent_message.cipher), base64StringToArrayBuffer(message.sent_message.AES));
                    image_url = message.image_url || null;
                }
            } else {
                text_message = message.message || null;
                image_url = message.image_url || null;
            }

            if (text_message || image_url) {
                if (newMessage) {
                    if (message.child_message) {
                        addSnapNotice(null, "New message")
                        newMessage = false;
                        message_seen(message.message_id);
                        update_message_status(STATUS_RECEIVED, getActivePerson());
                    }
                }
                if (messageType === 'you') {
                    addSnapMessage(message.message_id, text_message, null, save, image_url || null, message.reply_id || null, message.timestamp);
                } else {
                    addSnapMessage(message.message_id, text_message, getActivePerson(), save, image_url || null, message.reply_id || null, message.timestamp);
                }
            }
        }
    }

    process_temp_messages(getActivePerson());

    setTimeout(function () {
        var preloader = document.getElementById('preloader');
        preloader.style.display = 'none';
        var inputBoxContainer = document.getElementById('input-box-container');
        inputBoxContainer.style.display = 'flex';
        // Scroll to the bottom
        var header_content = document.getElementById('header_content');
        header_content.style.display = 'inline-block';
        chatContainer.scrollTop = chatContainer.scrollHeight;
    }, 300); // Adjust the delay time as needed
}

function process_temp_messages(username) {
    $.ajax({
        type: 'POST',
        url: `/chat/process/temp/messages/`,
        dataType: 'json',
        data: JSON.stringify({
            receiver_username: username,
        }),
        success: function (response) {
            if (response.status === 'success') {

            } else {
                console.error('Error loading messages:', response.error);
            }
        },
        error: function (error) {
            console.error('Error loading messages:', error);
        }
    });
}

function get_user_public_keys(username, room) {
    $.ajax({
        type: 'POST',
        url: `/chat/get/public-keys/`,
        dataType: 'json',
        data: JSON.stringify({
            receiver_username: username,
        }),
        success: function (response) {
            if (response.status === 'success') {
                (async () => {
                    await initialize_keys(room, response.public_keys);
                })();
            } else {
                console.error('Error loading messages:', response.error);
            }
        },
        error: function (error) {
            console.error('Error loading messages:', error);
        }
    });
}

async function get_device_public_keys(username, room, device_id) {
    $.ajax({
        type: 'POST',
        url: `/chat/get/device/public-keys/`,
        dataType: 'json',
        data: JSON.stringify({
            receiver_username: username,
            receiver_device_id: device_id
        }),
        success: async function (response) {
            if (response.status === 'success') {
                await initialize_single_key(room, response.public_keys, device_id);
            } else {
                console.error('Error loading messages:', response.error);
            }
        },
        error: async function (error) {
            console.error('Error loading messages:', error);
        }
    });
}

async function get_user_private_keys_secondary() {
    $.ajax({
        type: 'POST',
        url: `/chat/get/private-keys/secondary/`,
        dataType: 'json',
        success: async function (response) {
            if (response.status === 'success') {
                saveSecondaryKey(response.private_key.key, response.private_key.token);
                device_public_keys[response.device_id] = response.public_key;
                await initialize_asymmetric_devices();
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

function getActivePerson() {
    var activePersonElement = document.querySelector('.person.active');

    if (activePersonElement) {
        return activePersonElement.getAttribute('data-chat');
    } else {
        return null;
    }
}

function getActiveRoom() {
    var activePersonElement = document.querySelector('.person.active');
    if (activePersonElement) {
        return activePersonElement.getAttribute('data-room');
    } else {
        return null;
    }
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

function resetActiveness() {
    // Get all elements with the class 'person'
    const personElements = document.querySelectorAll('.person');

    // Remove the 'active' class from each element
    personElements.forEach((person) => {
        person.classList.remove('active');
    });
}

function adjustChatHeight(reduce) {
    const isMobile = window.innerWidth <= 767;
    if (reduce) {
        const inputBoxHeight = document.getElementById('input-box-container').offsetHeight;
        const chatContainer = document.getElementById('snap-ui-container');
        if (isMobile) {
            chatContainer.style.height = `calc(80vh - ${inputBoxHeight}px)`;

        } else {
            chatContainer.style.height = `calc(85vh - ${inputBoxHeight}px)`;
        }
        chatContainer.scrollTop = chatContainer.scrollHeight;

    } else {
        const chatContainer = document.getElementById('snap-ui-container');
        if (isMobile) {
            chatContainer.style.height = '80vh';
        } else {
            chatContainer.style.height = '85vh';
        }
        // Scroll to the bottom
        chatContainer.scrollTop = chatContainer.scrollHeight;
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

    const ulElement = document.querySelector('.people');
    const userElements = ulElement.querySelectorAll('.person');

    userElements.forEach(function (personElement) {
        const timeElement = personElement.querySelector('.time');
        if (timeElement) {
            const timestamp = timeElement.dataset.timestamp;
            if (timestamp) {
                timeElement.textContent = getFormattedTime(timestamp);
            }
        }
    });
    document.addEventListener("visibilitychange", function () {
        if (document.visibilityState === "visible") {
            const returnFromAddPerson = sessionStorage.getItem('return_from_add_person');

            if (returnFromAddPerson === 'true') {
                // Clear the session variable
                sessionStorage.removeItem('return_from_add_person');
                // Perform the desired action (e.g., refresh the page)
                location.reload();
            }
        }
    });

    let text = document.getElementById('feature_message');
    if (text) {
        text.textContent = display_feature_message();
    }
});


// Function to group messages by date
function groupMessagesByDate(messages) {
    return messages.reduce(function (accumulator, currentMessage) {
        const date = new Date(currentMessage.timestamp);
        const formattedDate = date.toISOString().split('T')[0]; // Format as YYYY-MM-DD
        // Check if there's a section for the date, if not, create it
        if (!accumulator[formattedDate]) {
            accumulator[formattedDate] = [];
        }
        accumulator[formattedDate].push(currentMessage);
        return accumulator;
    }, {});
}

function getMessageElementById(messageId) {
    // Retrieve the HTML element with the specified ID
    const repliedMessageElement = document.getElementById(messageId);

    // Check if the element is found
    if (repliedMessageElement) {
        return {
            element: repliedMessageElement
        };
    } else {
        /// Return an object with textContent as null, other attributes as null, and the HTML element as null
        return {
            element: null
        };
    }
}

function getMessageContentByID(message_id) {
    var result = getMessageElementById(message_id)
    if (result) {
        return Array.from(result.element.childNodes)
            .filter(node => node.nodeType === Node.TEXT_NODE)
            .map(node => node.textContent)
            .join('')
    } else {
        return null;
    }
}

function insert_new_user(username, room, fullname, timestamp, img_src) {
    var userList = document.querySelector('.people');

    var newListElement = document.createElement('li');
    newListElement.className = 'person context-menu-trigger';
    newListElement.setAttribute('data-chat', username);
    newListElement.setAttribute('data-room', room)
    newListElement.onclick = function () {
        load_chat(username);
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
        if (getActivePerson() !== null) {
            chatSocket.send(JSON.stringify({
                'type': 'initialize_receiver',
                'receiver_username': getActivePerson(),
            }));
        }
    };

    chatSocket.onclose = function (event) {
        if (event.code !== 1000) {
            console.log('Reconnecting...');
            // setTimeout(initialize_socket, 10000);
        }
    };

    chatSocket.onerror = function (error) {
        console.error('WebSocket encountered an error:', error);
    };

    chatSocket.onmessage = async function (e) {
        if (e.data instanceof Blob) {
            const reader = new FileReader();

            reader.onload = async function (event) {
                var snapUiContainer = document.getElementById('snap-ui-container');

                const binaryData = new Uint8Array(event.target.result);
                var data = msgpack.decode(binaryData);

                // Extract text data
                const type = data.type;
                if (type === 0) {
                    if (data.sender_username === getActivePerson()) {
                        if (encryption_instance[data.device_id]) {
                            const messageType = data.sender_username === userUsername ? 'you' : getActivePerson();
                            await encryption_instance[data.device_id].setReceiverKey_RAW(data.public_key);
                            let text_message = await encryption_instance[data.device_id].recv(data.message);
                            if (messageType === "you") {
                                addSnapMessage(data.message_id, text_message, null, null, null, data.reply_id || null)
                            } else {
                                addSnapMessage(data.message_id, text_message, getActivePerson(), null, null, data.reply_id || null)
                            }

                            snapUiContainer.scrollTop = snapUiContainer.scrollHeight;

                            // Hide the loading icon after receiving a message
                            const loadingIcon = document.getElementById('loading');
                            loadingIcon.style.display = 'none';
                            handleNewMessage(getActivePerson(), data.message_id, false);
                            message_seen(data.message_id);
                            update_message_status(STATUS_RECEIVED, data.sender_username);
                        }
                    } else {
                        handleNewMessage(data.sender_username, data.message_id, true);
                    }
                } else if (type === 1) {
                    const message_id = data.message_id;
                    const message = data.message;
                    const sender_username = data.sender_username;
                    const public_key = data.public_key;
                    const device_id = data.device_id;
                    if (sender_username === getActivePerson()) {
                        await encryption_instance[device_id].setReceiverKey_RAW(public_key);
                        let decrypted_cipher = null;
                        if (message !== '') {
                            decrypted_cipher = await encryption_instance[device_id].recvImage(data.image_bytes, message);
                        } else {
                            decrypted_cipher = await encryption_instance[device_id].recvImage(data.image_bytes, null);
                        }

                        const imageBlob = new Blob([decrypted_cipher.image_bytes], {type: 'image/webp'});
                        const messageType = sender_username === userUsername ? 'you' : getActivePerson();
                        if (message !== '') {
                            if (messageType === "you") {
                                updateImage(imageBlob, null, message_id, null, decrypted_cipher.text_message);
                            } else {
                                updateImage(imageBlob, getActivePerson(), message_id, null, decrypted_cipher.text_message);
                            }
                        } else {
                            if (messageType === "you") {
                                updateImage(imageBlob, null, message_id, null, null);
                            } else {
                                updateImage(imageBlob, getActivePerson(), message_id, null, null);
                            }
                        }

                        snapUiContainer.scrollTop = snapUiContainer.scrollHeight;


                        // Hide the loading icon after receiving a message
                        const loadingIcon = document.getElementById('loading');
                        loadingIcon.style.display = 'none';

                        message_seen(message_id);
                    } else {
                        update_message_status(STATUS_RECEIVED, sender_username);
                    }
                } else if (type === 2) {
                    if (data.room === getActiveRoom()) {
                        let message = await decryptSentMessage(data.cipher, data.AES);
                        addSnapMessage(data.message_id, message, null, null, null, data.reply_id || null)
                        update_message_status(STATUS_DELIVERED, getUsernameByRoom(data.room));
                    } else {
                        handleNewMessage(getUsernameByRoom(data.room), data.message_id, true);
                    }
                } else if (type === 3) {
                    const message_id = data.message_id;
                    const cipher_text = data.cipher;
                    const AES = data.AES;
                    const room = data.room;

                    if (room === getActiveRoom()) {

                        let decrypted_cipher = await asymmetric_private_instance.decrypt_Image_Message(data.image_bytes, cipher_text, AES)
                        if (decrypted_cipher) {
                            const imageBlob = new Blob([decrypted_cipher.cipher_bytes], {type: 'image/webp'});
                            updateImage(imageBlob, null, message_id, null, decrypted_cipher.text_message || null);
                        }
                        const loadingIcon = document.getElementById('loading');
                        loadingIcon.style.display = 'none';
                    }
                }
            };

            reader.readAsArrayBuffer(e.data);
        } else {
            const data = JSON.parse(e.data);
            if (data.type === 'user_status') {
                if (data.username === getActivePerson()) {
                    const heading_name = document.getElementById('heading_name');
                    heading_name.innerHTML = `${data.username}`;

                    const newUserStatusSpan = document.createElement('span');
                    newUserStatusSpan.className = 'preview';
                    newUserStatusSpan.style.fontSize = '14px'; // Set the desired style
                    newUserStatusSpan.style.color = 'rgb(217,217,217)'; // Set the desired style
                    newUserStatusSpan.style.marginLeft = 8;
                    newUserStatusSpan.textContent = `${data.status}`;

                    heading_name.appendChild(newUserStatusSpan);
                    var personElement = document.querySelector(`[data-chat='${data.username}']`);
                    if (personElement) {
                        personElement.setAttribute('status', `${data.status}`);
                    }
                }
            } else if (data.type === 'device_online') {
                if (data.room === getActiveRoom()) {
                    if (data.public_keys) {
                        await initialize_single_key(data.room, data.public_keys, data.device_id);
                        for (const device_id in encryption_instance) {
                            if (!data.active_device_ids.includes(device_id)) {
                                delete encryption_instance[device_id];
                            }
                        }
                    } else {
                        if (encryption_instance[data.device_id]) {
                            delete encryption_instance[data.device_id];
                            if (Object.keys(encryption_instance).length === 0) {
                                get_user_public_keys(getActivePerson(), getActiveRoom());
                            }
                        }
                    }
                }
            } else if (data.type === 'device_public_key_change') {
                if (data.room === getActiveRoom()) {
                    await initialize_single_key(data.room, data.public_keys, data.device_id);
                }
            } else if (data.type === 'message_sent') {
                if (data.data_type === 'bytes') {
                    updateImage(bytes_webpBlob, null, data.message_id, null, bytes_message)
                    bytes_webpBlob = null;
                } else if (data.data_type === 'text') {
                    updateSentMessage(bytes_message, data.message_id, sent_reply_id || null);
                    sent_reply_id = null;
                }
                bytes_message = null;
                const loadingIcon = document.getElementById('loading');
                loadingIcon.style.display = 'none';
            } else if (data.type === 'save_message') {
                if (data.sender_username === getActivePerson() || data.sender_username === userUsername) {
                    const message_element = getMessageElementById(data.message_id)
                    if (message_element) {
                        if (data.save_message) {
                            message_element.element.setAttribute('saved', '');
                        } else {
                            message_element.element.removeAttribute('saved');
                        }
                    }
                }
            } else if (data.type === 'delete_message') {
                if (data.sender_username === getActivePerson() || data.sender_username === userUsername) {
                    const result = getMessageElementById(data.message_id)
                    let deleted = null;

                    let from = result.element.getAttribute('from')
                    if (from === 'Me') {
                        deleted = "You deleted a message";
                    } else {
                        deleted = `${getActivePerson()} deleted a message`;
                    }

                    const snapNoticeElement = document.createElement('snap-notice');
                    snapNoticeElement.textContent = deleted;
                    result.element.replaceWith(snapNoticeElement);
                }
            } else if (data.type === 'new_message_background') {
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
                if (data.username === getActivePerson()) {
                    close_all_chats();
                }
                remove_user(data.username);
            } else if (data.type === 'chat_sent_message') {
                if (data.room === getActiveRoom()) {
                    let message = await decryptSentMessage(data.cipher, data.AES);
                    addSnapMessage(data.message_id, message, null, null, null, data.reply_id || null)
                    update_message_status(STATUS_DELIVERED, getUsernameByRoom(data.room));
                } else {
                    handleNewMessage(getUsernameByRoom(data.room), data.message_id, true);
                }
            } else {
                if (data.sender_username === getActivePerson()) {
                    if (encryption_instance[data.device_id]) {
                        const messageType = data.sender_username === userUsername ? 'you' : getActivePerson();
                        await encryption_instance[data.device_id].setReceiverKey_JWK(data.public_key);
                        let text_message = await encryption_instance[data.device_id].recv(data.message);
                        if (messageType === "you") {
                            addSnapMessage(data.message_id, text_message, null, null, null, data.reply_id || null)
                        } else {
                            addSnapMessage(data.message_id, text_message, getActivePerson(), null, null, data.reply_id || null)
                        }

                        // Scroll to the bottom
                        var snapUiContainer = document.getElementById('snap-ui-container');
                        snapUiContainer.scrollTop = snapUiContainer.scrollHeight;

                        // Hide the loading icon after receiving a message
                        const loadingIcon = document.getElementById('loading');
                        loadingIcon.style.display = 'none';
                        handleNewMessage(getActivePerson(), data.message_id, false);
                        message_seen(data.message_id);
                        update_message_status(STATUS_RECEIVED, data.sender_username);
                    }
                } else {
                    handleNewMessage(data.sender_username, data.message_id, true);
                }
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

function message_seen(message_id) {
    chatSocket.send(JSON.stringify({
        'type': 'message_seen',
        'message_id': message_id,
    }));
}

const updateSentMessage = function (message, message_id, reply_id = null) {
    if (message !== '') {
        addSnapMessage(message_id, message, null, storeMessage, null, reply_id || null);
    }

    // Scroll to the bottom
    var snapUiContainer = document.getElementById('snap-ui-container');
    snapUiContainer.scrollTop = snapUiContainer.scrollHeight;

    if (reply_id) {
        closeReplyMessageHolder();
    }

    handleNewMessage(getActivePerson(), message_id, false);
    update_message_status(STATUS_DELIVERED, getActivePerson());
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

function addSnapMessage(message_id = null, text = null, from = null, saved = null, imageUrl = null, repliedMessage = null, timestamp) {
    // Create a new snap-message element
    var snapMessage = document.createElement('snap-message');

    // Attach the context menu event listener
    snapMessage.addEventListener('contextmenu', function (event) {
        // Pass the snapData to the showContextMenu function
        event.preventDefault();
        if (from) {
            showContextMenu(event, text, from, message_id, imageUrl || null, repliedMessage || null);
        } else {
            showContextMenu(event, text, null, message_id, imageUrl || null, repliedMessage || null);
        }
    });

    // Set the text content
    if (text) {
        snapMessage.textContent = text;
        snapMessage.style.wordBreak = 'break-all';
    }

    if (message_id) {
        snapMessage.setAttribute('id', message_id);
    }

    // Set 'from' attribute if provided
    if (from) {
        snapMessage.setAttribute('from', from);
    }

    // Set 'saved' attribute if provided
    if (saved) {
        snapMessage.setAttribute('saved', '');
    }

    if (timestamp) {
        snapMessage.setAttribute('timestamp', getFormattedTime(timestamp));
    } else {
        snapMessage.setAttribute('timestamp', getFormattedTime(message_id));
    }

    // Check if imageUrl is provided
    if (imageUrl) {
        // Create an img element for the image
        var imageElement = document.createElement('img');
        imageElement.src = imageUrl; // Set the image URL
        imageElement.alt = 'Image'; // Set the alt attribute
        imageElement.width = 200;
        imageElement.classList = 'message_image';

        // Append the image element to the snap-message element
        snapMessage.prepend(imageElement);

        imageElement.onload = function () {
            var snapUiContainer = document.getElementById('snap-ui-container');
            snapUiContainer.scrollTop = snapUiContainer.scrollHeight;
        };
    }

    if (repliedMessage) {
        const result = getMessageElementById(repliedMessage);

        if (result) {
            const imgElement = result.element.querySelector(':scope > img');

            if (imgElement) {
                const clonedElement = document.createElement(result.element.tagName);
                clonedElement.className = result.element.className;
                clonedElement.id = `reply_${result.element.id}`;
                clonedElement.setAttribute('from', result.element.getAttribute('from'));

                const clonedImageElement = imgElement.cloneNode(true);
                clonedImageElement.style.width = '100px';
                // Append the cloned image element to the snapMessage
                clonedElement.prepend(clonedImageElement);
                snapMessage.prepend(clonedElement)

                // Handle other properties of the snap-message element if needed
            } else {

                // Handle non-image elements
                const clonedElement = document.createElement(result.element.tagName);
                clonedElement.className = result.element.className;
                clonedElement.id = `reply_${result.element.id}`;

                const textNode = document.createTextNode(getMessageContentByID(result.element.id));

                clonedElement.appendChild(textNode);
                clonedElement.setAttribute('from', result.element.getAttribute('from'));

                snapMessage.prepend(clonedElement);
            }
        } else {
            const no_message = document.createElement('snap-message');
            no_message.removeAttribute('from');
            no_message.textContent = 'This message was deleted';

            snapMessage.prepend(no_message);
        }
    }

    // Get the Snap UI container
    var snapUiContainer = document.getElementById('snap-ui-container');

    snapUiContainer.prepend(snapMessage);
    snapUiContainer.scrollTop = snapUiContainer.scrollHeight;

    closeReplyMessageHolder();
}

function addSnapNotice(date, message) {
    var snapUiContainer = document.getElementById('snap-ui-container');
    var snap_notice = document.createElement('snap-notice')
    if (date) {
        snap_notice.textContent = createMessageDateString(date);
    }

    if (message) {
        snap_notice.textContent = message;
    }
    snapUiContainer.prepend(snap_notice);
}

const updateImage = function (image, from, message_id, input, message = null) {
    // Create an object URL from the Blob
    const imageUrl = URL.createObjectURL(image);
    if (from) {
        addSnapMessage(message_id, message, from, null, imageUrl, null)
    } else {
        addSnapMessage(message_id, message, null, null, imageUrl, null)
    }
    updateImageLabelIcon(input)
}

function updateImageLabelIcon(input) {
    // Get the file input and its value
    if (input && input.files && input.files[0]) {
        var fileName = input.files[0].name;
        var imageUrl = URL.createObjectURL(input.files[0]);

        // Change the label icon based on whether an image is selected
        if (fileName) {
            document.getElementById('image_input_label').style.display = 'none';
            document.getElementById('selectedImage').src = imageUrl;
            document.getElementById('selectedImage').style.display = 'block';
        } else {
            document.getElementById('image_input_label').style.display = 'flex';
            document.getElementById('selectedImage').style.display = 'none';
        }
    }
}

// Section: User list context menu
// Get all elements with the class 'context-menu-trigger'
const contextMenuTriggers = document.querySelectorAll('.context-menu-trigger');

// Create a variable to store the currently active context menu
let activeContextMenu = null;

// Function to hide the context menu
function hideContextMenu_profile() {
    // Check if there is an active context menu
    if (activeContextMenu) {
        // Hide the context menu
        activeContextMenu.style.display = 'none';

        // Remove the click event listener from the document
        document.removeEventListener('click', hideContextMenu);

        // Reset the active context menu variable
        activeContextMenu = null;
    }
}

// Iterate through each trigger and attach the context menu listener
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
async function retrieveAndImportKeys(username) {
    let roomData = JSON.parse(localStorage.getItem(username));

    if (roomData && roomData.type && roomData.private_keys) {
        if (roomData.type === 'sender') {
            let ikPrivateKeyData = base64StringToArrayBuffer(roomData.private_keys.ikPrivateKeyData);
            let ekPrivateKeyData = base64StringToArrayBuffer(roomData.private_keys.ekPrivateKeyData);

            let importedIkPrivateKey = await crypto.subtle.importKey(
                'raw',
                ikPrivateKeyData,
                {name: 'HKDF'},
                false,
                ['deriveKey']
            );
            let importedEkPrivateKey = await crypto.subtle.importKey(
                'raw',
                ekPrivateKeyData,
                {name: 'HKDF'},
                false,
                ['deriveKey']
            );

            return {
                ikPrivateKey: importedIkPrivateKey,
                ekPrivateKey: importedEkPrivateKey
            };
        } else if (roomData.type === 'receiver') {
            let ikPrivateKey = base64StringToArrayBuffer(roomData.private_keys.ikPrivateKey);
            let spkPrivateKey = base64StringToArrayBuffer(roomData.private_keys.spkPrivateKey);
            let opkPrivateKey = base64StringToArrayBuffer(roomData.private_keys.opkPrivateKey);
            let dhratchet_key = base64StringToArrayBuffer(roomData.private_keys.dhratchet_key);

            let importedIkPrivateKey = await crypto.subtle.importKey(
                'raw',
                ikPrivateKey,
                {name: 'HKDF'},
                false,
                ['deriveKey']
            );
            let importedSPKPrivateKey = await crypto.subtle.importKey(
                'raw',
                spkPrivateKey,
                {name: 'HKDF'},
                false,
                ['deriveKey']
            );

            let importedOPKPrivateKey = await crypto.subtle.importKey(
                'raw',
                opkPrivateKey,
                {name: 'HKDF'},
                false,
                ['deriveKey']
            );
            let importedDHRatchetKey = await crypto.subtle.importKey(
                'raw',
                dhratchet_key,
                {name: 'HKDF'},
                false,
                ['deriveKey']
            );

            return {
                ikPrivateKey: importedIkPrivateKey,
                spkPrivateKey: importedSPKPrivateKey,
                opkPrivateKey: importedOPKPrivateKey,
                dhRatchetPrivateKey: importedDHRatchetKey
            };
        }
    } else {
        console.log('No keys found for this username');
        return null;
    }
}

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
    // Decode the base64 string to a binary string
    let binaryString = window.atob(base64);
    let length = binaryString.length;

    // Create a Uint8Array to hold the binary data
    let bytes = new Uint8Array(length);

    // Fill the Uint8Array with the binary data
    for (let i = 0; i < length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }

    return bytes; // Return the Uint8Array directly
}

async function import_public_keys(keys) {
    let key = base64StringToArrayBuffer(keys[0]);
    let ikpublic_key = await crypto.subtle.importKey(
        'spki',
        key,
        {name: 'ECDH', namedCurve: 'P-256'},
        true,
        []
    );
}

async function initialize_keys(room, publicKeysInfo) {
    if (asymmetric_private_instance) {
        let roomData = getKeysByRoom(getActiveRoom());
        if (roomData) {
            for (const device_id in publicKeysInfo) {
                if (publicKeysInfo.hasOwnProperty(device_id)) {
                    const keysInfo = publicKeysInfo[device_id];

                    let encryptionInstance;
                    if (roomData.type === 'sender') {
                        encryptionInstance = new Alice(room, device_id, asymmetric_private_instance);
                    } else if (roomData.type === 'receiver') {
                        encryptionInstance = new Bob(room, device_id, asymmetric_private_instance);
                    }
                    await encryptionInstance.retrieveAndImportKeys();
                    await encryptionInstance.x3dh(keysInfo.public_keys);
                    await encryptionInstance.initRatchets();
                    await encryptionInstance.setReceiverKey(keysInfo.ratchet_public_key);
                    encryption_instance[device_id] = encryptionInstance;
                }
            }
        }
    }
}

async function initialize_single_key(room, keysInfo, device_id) {
    if (asymmetric_private_instance) {
        let roomData = getKeysByRoom(getActiveRoom());
        let encryptionInstance;
        if (roomData) {
            if (roomData.type === 'sender') {
                encryptionInstance = new Alice(room, device_id, asymmetric_private_instance);
            } else if (roomData.type === 'receiver') {
                encryptionInstance = new Bob(room, device_id, asymmetric_private_instance);
            }
            await encryptionInstance.retrieveAndImportKeys();
            await encryptionInstance.x3dh(keysInfo.public_keys);
            await encryptionInstance.initRatchets();
            await encryptionInstance.setReceiverKey(keysInfo.ratchet_public_key);
            encryption_instance[device_id] = encryptionInstance;
        }
    }
}

async function initialize_ratchet_encryption_temp(room, keysInfo, ratchet_key, device_id) {
    let roomData = getKeysByRoom(getActiveRoom());
    let encryptionInstance;

    if (roomData && asymmetric_private_instance) {
        if (roomData.type === 'sender') {
            encryptionInstance = new Alice(room, device_id, asymmetric_private_instance);
        } else if (roomData.type === 'receiver') {
            encryptionInstance = new Bob(room, device_id, asymmetric_private_instance);
        }
        await encryptionInstance.retrieveAndImportKeys();
        await encryptionInstance.x3dh(keysInfo);
        await encryptionInstance.initRatchets();
        await encryptionInstance.setReceiverKey(ratchet_key);
        return encryptionInstance;
    } else {
        return null;
    }
}

async function encryption_send(message) {
    const responses = {};

    const instances = Object.values(encryption_instance);

    const sendPromises = instances.map(async (instance) => {
        responses[instance.device_id] = await instance.send(message);
    });

    await Promise.all(sendPromises);

    return responses;
}

function imageEncryption_send(image_bytes, message) {
    const instances = Object.values(encryption_instance);
    const asym_instances = Object.values(asymmetricInstances);

    $.ajax({
        type: 'POST',
        url: `/chat/generate/message/id/`,
        dataType: 'json',
        success: function (response) {
            if (response.status === 'success') {
                sendMessagesConcurrently(instances, response.message_id, image_bytes, message);
                encryptSentImageMessages(asym_instances, response.message_id, image_bytes, message);
            } else {
                console.error('Error loading messages:', response.error);
            }
        },
        error: function (error) {
            console.error('Error loading messages:', error);
        }
    });

}

async function sendMessagesConcurrently(instances, messageId, image_bytes, message) {
    instances.forEach(async (instance, index) => {
        instance.sendImage(image_bytes, message)
            .then(encryptedMessage => {
                const flag = index === 0 ? 1 : undefined;
                const data = {
                    type: 1,
                    message: encryptedMessage.cipher,
                    storeMessage: storeMessage,
                    public_key: encryptedMessage.ratchet_key,
                    device_id: instance.device_id,
                    message_id: messageId,
                    flag: flag,
                    key_version: encryptedMessage.key_version,
                    image_bytes: encryptedMessage.bytes_cipher
                };
                var encodedData = msgpack.encode(data);
                chatSocket.send(encodedData);
            })
            .catch(error => {
                console.error('Error encrypting message:', error);
            });
    });
}

async function initialize_asymmetric_devices() {
    if (device_public_keys) {
        for (const [device_id, public_key] of Object.entries(device_public_keys)) {
            const asymmetricInstance = new asymmetric(device_id);

            await asymmetricInstance.setReceiverKey(public_key);
            asymmetricInstances[device_id] = asymmetricInstance;
        }
    }
}

async function encryptSentMessage(message) {
    const encryptedMessages = {};
    for (const device_id in asymmetricInstances) {
        if (asymmetricInstances.hasOwnProperty(device_id)) {
            const instance = asymmetricInstances[device_id];
            const encryptedMessage = await instance.encrypt(message);
            encryptedMessages[device_id] = encryptedMessage;
        }
    }
    return encryptedMessages;
}

async function encryptSentImageMessages(instances, messageId, image_bytes, message) {
    instances.forEach(async (instance, index) => {
        instance.encryptImageBytes(image_bytes, message)
            .then(encryptedMessage => {
                if (encryptedMessage) {
                    const messageObject = {
                        type: 2,
                        message: encryptedMessage.ciphertext,
                        AES: encryptedMessage.AES,
                        device_id: instance.device_id,
                        message_id: messageId,
                        image_bytes: encryptedMessage.cipherbytes
                    };
                    var encodedData = msgpack.encode(messageObject);
                    chatSocket.send(encodedData);
                }
            })
            .catch(error => {
                console.error('Error encrypting message:', error);
            });
    });
}

async function decryptSentMessage(cipher, aes) {
    return await asymmetric_private_instance.decryptMessage(cipher, aes);
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