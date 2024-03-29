"use strict";

// Section: ContextMenu
const saveTextElement = document.getElementById('save_text');
const delete_message_context = document.getElementById('delete_message_context');

let text = null;
let from = null;
let message_id = null;
let imageUrl = null;
let reply_id = null;

function showContextMenu(event, texts, froms, message_id_arg, image_url, reply_ids) {
    event.preventDefault();

    // Access the context menu directly
    const contextMenu = document.getElementById('contextMenu');
    const result = getMessageElementById(message_id_arg);


    if (result.element.getAttribute('saved') === '') {
        saveTextElement.innerHTML = '<i class="fa fa-save"></i> Unsave';
        saveTextElement.onclick = () => handleContextMenu('unsave');
    } else {
        saveTextElement.innerHTML = '<i class="fa fa-save"></i> Save in chat';
        saveTextElement.onclick = () => handleContextMenu('save');
    }

    let from = result.element.getAttribute('from')
    if (from === 'Me') {
        delete_message_context.style.display = 'block';
    } else {
        delete_message_context.style.display = 'none';
    }

    // Set the position of the context menu
    contextMenu.style.display = 'block';
    contextMenu.style.left = event.pageX + 'px';
    contextMenu.style.top = event.pageY + 'px';

    if (texts) {
        text = texts;
    }

    if (froms) {
        from = froms;
    }

    if (message_id_arg) {
        message_id = message_id_arg;
    }

    if (image_url) {
        imageUrl = image_url;
    }

    if (reply_ids) {
        reply_id = reply_ids;
    }

    // Hide the context menu when clicking outside
    document.addEventListener('click', hideContextMenu);
}

// Handle context menu item click
function handleContextMenu(option) {
    if (option === 'reply') {

        var textarea = document.getElementById("input");

        // Focus on the textarea
        textarea.focus();

        adjustChatHeight(true);

        var snapMessage = document.createElement('snap-message');

        snapMessage.textContent = text;
        snapMessage.style.wordBreak = 'break-all';

        if (from) {
            snapMessage.setAttribute('from', from);
        }

        if (message_id) {
            snapMessage.setAttribute('id', message_id);
        }

        if (imageUrl) {
            // Create an img element for the image
            var imageElement = document.createElement('img');
            imageElement.src = imageUrl; // Set the image URL
            imageElement.alt = 'Image'; // Set the alt attribute
            imageElement.width = 100;

            // Append the image element to the snap-message element
            snapMessage.prepend(imageElement);
        }

        var reply_message_holder = document.getElementById('reply_message_holder');
        var close_reply = document.getElementById('close_reply');
        close_reply.style.display = 'block';
        var specific_element_to_remove = reply_message_holder.querySelector('snap-message');
        if (specific_element_to_remove) {
            reply_message_holder.removeChild(specific_element_to_remove);
        }
        reply_message_holder.prepend(snapMessage);
    } else if (option === 'save') {
        saveMessageToServer(message_id, true, reply_id || null, imageUrl || null)
    } else if (option === 'unsave') {
        saveMessageToServer(message_id, false, null)
    } else if (option === 'delete') {
        deleteMessage(message_id);
    }
    text = null;
    from = null;
    message_id = null;
    imageUrl = null;
    reply_id = null;
    hideContextMenu();
}

// Hide the context menu
function hideContextMenu() {
    const contextMenu = document.getElementById('contextMenu');
    contextMenu.style.display = 'none';

    // Remove the click event listener
    document.removeEventListener('click', hideContextMenu);
}

function saveMessageToServer(message_id, isSave, reply_id, image_url = null) {
    const message = getMessageContentByID(message_id)
    const result = getMessageElementById(message_id)

    let from = result.element.getAttribute('from')
    let sender = null;
    let receiver = null;
    if (from !== 'Me') {
        sender = from;
        receiver = userUsername;
    } else {
        sender = userUsername;
        receiver = getActivePerson()
    }
    if (isSave) {
        if (image_url) {
            let image = result.element.querySelector('.message_image');
            if (image) {
                const imageUrl = image.src
                if (imageUrl) {
                    fetch(imageUrl)
                        .then(response => response.blob())
                        .then(blob => {
                            const reader = new FileReader();
                            reader.onloadend = function () {
                                const imageData = reader.result;

                                const blobImageData = new Blob([imageData]);
                                const formData = new FormData();
                                formData.append('image_data', blobImageData);
                                formData.append('message_id', message_id);

                                $.ajax({
                                    url: '/chat/upload/image/',
                                    type: 'POST',
                                    processData: false,
                                    contentType: false,
                                    data: formData,
                                    success: function (data) {
                                        chatSocket.send(JSON.stringify({
                                            'type': 'save_message',
                                            'save_message': isSave,
                                            'message_id': message_id,
                                            'message': message,
                                            'image_url': data.image_url,
                                            'sender': sender,
                                            'receiver': receiver,
                                        }));
                                    },
                                    error: function (data) {
                                        alert(data.error)
                                    }
                                });
                            };
                            reader.readAsArrayBuffer(blob);
                        })
                        .catch(error => {
                            console.error('Error fetching image:', error);
                        });
                }
            }
        } else {
            chatSocket.send(JSON.stringify({
                'type': 'save_message',
                'save_message': isSave,
                'message_id': message_id,
                'message': message,
                'reply_id': reply_id || null,
                'sender': sender,
                'receiver': receiver,
            }));
        }
    } else {
        chatSocket.send(JSON.stringify({
            'type': 'save_message',
            'save_message': isSave,
            'message_id': message_id,
        }));
    }
}

function closeReplyMessageHolder() {
    adjustChatHeight(false)
    var replyMessageHolder = document.getElementById('reply_message_holder');
    if (replyMessageHolder) {
        // Find and remove the snap-message element
        var snapMessage = replyMessageHolder.querySelector('snap-message');
        if (snapMessage) {
            snapMessage.remove();
        }
    }
    var close_reply = document.getElementById('close_reply');
    close_reply.style.display = 'none';
}

function deleteMessage(message_id) {
    chatSocket.send(JSON.stringify({
        'type': 'delete_message',
        'message_id': message_id,
        'sender_username': userUsername,
    }));
}

// Context Menu

// Section: Handle Hover
function handleHover(event) {
    const hoveredElement = event.target;

    // Find the direct parent (container) of the snap-message elements
    const container = hoveredElement.parentNode;

    // Find all snap-message elements in the container
    const snapMessages = container.querySelectorAll('snap-message:not(snap-message snap-message)');

    // Find the index of the hovered element among its siblings
    const index = Array.from(snapMessages).indexOf(hoveredElement);

    // Traverse the chain to find the actual first element
    let actualFirstElement = hoveredElement;
    for (let i = index; i < snapMessages.length - 1; i++) {
        const sibling = snapMessages[i + 1];
        if (sibling.classList.contains('hasFollower')) {
            actualFirstElement = sibling;
        } else {
            break;
        }

    }

    const shadowRoot = actualFirstElement.shadowRoot;

    if (shadowRoot) {
        const additionalText = shadowRoot.querySelector('.additional-text');

        if (additionalText) {
            additionalText.style.display = 'inline';
            additionalText.textContent = hoveredElement.getAttribute('timestamp')
        }
    }
}

function handleHoverEnd(event) {
    const hoveredElement = event.target;

    // Find the direct parent (container) of the snap-message elements
    const container = hoveredElement.parentNode;

    // Find all snap-message elements in the container
    const snapMessages = container.querySelectorAll('snap-message');

    // Iterate over each snap-message element and hide additional text
    snapMessages.forEach((snapMessage) => {
        const shadowRoot = snapMessage.shadowRoot;
        if (shadowRoot) {
            const additionalText = shadowRoot.querySelector('.additional-text');
            if (additionalText) {
                additionalText.style.display = 'none';
            }
        }
    });
}

// Handle Hover End

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

// Function to get the value of a cookie by its name
function getCookie(name) {
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
        const [cookieName, cookieValue] = cookie.trim().split('=');
        if (cookieName === name) {
            return decodeURIComponent(cookieValue);
        }
    }
    return null;
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
            device_id: getCookie('device_id')
        }),
        success: function (response) {
            if (response.status === 'success') {
                if (response.generate_keys) {
                    if (response.keys.private_keys.type === 0) {
                        saveKeys_sender(getActiveRoom(), response.keys.private_keys.version, response.keys.private_keys.ik_private_key, response.keys.private_keys.ek_private_key, response.keys.private_keys.dhratchet_private_key);
                    } else if (response.keys.private_keys.type === 1) {
                        saveKeys_receiver(getActiveRoom(), response.keys.private_keys.version, response.keys.private_keys.ik_private_key, response.keys.private_keys.spk_private_key, response.keys.private_keys.opk_private_key, response.keys.private_keys.dhratchet_private_key)
                    }
                }

                var messages = JSON.parse(response.data);
                (async () => {
                    await load_chat_message(messages, response.keys.public_keys);
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
                if (message.child_message.base_public_key) {
                    encryption = await initialize_ratchet_encryption_temp(getActiveRoom(), message.child_message.base_public_key, message.child_message.public_key, message.child_message.device_id);
                }
                if (encryption) {
                    if (message.child_message.public_key) {
                        await encryption.setReceiverKey(message.child_message.public_key);
                        if (message.child_message.bytes_cipher) {
                            if (message.child_message.cipher) {
                                let decrypted_cipher = await encryption.recvImage(base64StringToUint8Array(message.child_message.bytes_cipher), message.child_message.cipher);
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
                            text_message = await encryption.recv(message.child_message.cipher);
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
                    let decrypted_cipher = await decryptASYM_Image_Message(base64StringToUint8Array(message.sent_message.cipher_bytes), message.sent_message.cipher, message.sent_message.AES);
                    if (decrypted_cipher) {
                        const imageBlob = new Blob([decrypted_cipher.cipher_bytes], {type: 'image/webp'});
                        image_url = URL.createObjectURL(imageBlob);
                        text_message = decrypted_cipher.text_message;
                    } else {
                        text_message = message.message || null;
                        image_url = message.image_url || null;
                    }
                } else {
                    text_message = await decryptSentMessage(message.sent_message.cipher, message.sent_message.AES);
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
            device_id: getCookie('device_id')
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
            device_id: getCookie('device_id')
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

function get_device_public_keys(username, room, device_id) {
    let self_device_id = getCookie('device_id')
    $.ajax({
        type: 'POST',
        url: `/chat/get/device/public-keys/`,
        dataType: 'json',
        data: JSON.stringify({
            receiver_username: username,
            self_device_id: self_device_id,
            receiver_device_id: device_id
        }),
        success: function (response) {
            if (response.status === 'success') {
                (async () => {
                    await initialize_single_key(room, response.public_keys, device_id);
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

function get_user_private_keys_secondary() {
    let device_id = getCookie('device_id');
    $.ajax({
        type: 'POST',
        url: `/chat/get/private-keys/secondary/`,
        dataType: 'json',
        data: JSON.stringify({
            device_id: device_id
        }),
        success: function (response) {
            if (response.status === 'success') {
                saveSecondaryKey(response.private_key.key, response.private_key.token);
                device_public_keys[device_id] = response.public_key;
                (async () => {
                    await initialize_asymmetric_devices();
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

document.getElementById('input').addEventListener('input', function () {
    resizeTextarea();
});

function resizeTextarea() {
    var textarea = document.getElementById('input');
    var lineHeight = parseFloat(window.getComputedStyle(textarea).lineHeight);

    // Calculate the maximum height for 3 rows
    var maxHeight = lineHeight * 3;

    textarea.style.height = 'auto'; // Reset height to auto to calculate the actual height
    textarea.style.height = (textarea.scrollHeight > maxHeight) ? maxHeight + 'px' : textarea.scrollHeight + 'px';
}


document.addEventListener('DOMContentLoaded', function () {
    initialize_socket();
    if (key && key !== '') {
        saveSecondaryKey(key.key, key.token);
    }
    if (!getSecondaryKey()) {
        get_user_private_keys_secondary();
    } else {
        (async () => {
        await initialize_asymmetric_devices(device_public_keys);
    })();
    }

    displayImages();
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

    const messageInput = document.getElementById('input');
    let isTyping = false;
    let debounceTimeout;

    messageInput.addEventListener('input', function () {
        clearTimeout(debounceTimeout);

        if (!isTyping) {
            // User started typing
            isTyping = true;
            if (isWebSocketReady(chatSocket)) {
                chatSocket.send(JSON.stringify({
                    'type': 'typing_status',
                    'typing': true
                }));
            }
        }

        debounceTimeout = setTimeout(function () {
            // User stopped typing
            isTyping = false;
            if (isWebSocketReady(chatSocket)) {
                chatSocket.send(JSON.stringify({
                    'type': 'typing_status',
                    'typing': false
                }));
            }
        }, 500);
    });
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
    const web_socket_url = `${protocol}://` + window.location.host + `/ws/chat/?device_id=${getCookie('device_id')}`
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
                const binaryData = new Uint8Array(event.target.result);

                // Find delimiter indices
                const delimiterIndex1 = binaryData.indexOf('\n'.charCodeAt(0));
                const delimiterIndex2 = binaryData.indexOf('\n'.charCodeAt(0), delimiterIndex1 + 1);
                const delimiterIndex3 = binaryData.indexOf('\n'.charCodeAt(0), delimiterIndex2 + 1);
                const delimiterIndex4 = binaryData.indexOf('\n'.charCodeAt(0), delimiterIndex3 + 1);
                const delimiterIndex5 = binaryData.indexOf('\n'.charCodeAt(0), delimiterIndex4 + 1);
                const delimiterIndex6 = binaryData.indexOf('\n'.charCodeAt(0), delimiterIndex5 + 1);

                // Extract text data
                const type = parseInt(new TextDecoder().decode(binaryData.subarray(0, delimiterIndex1)), 10);
                if (type === 0) {
                    const message_id = new TextDecoder().decode(binaryData.subarray(delimiterIndex1 + 1, delimiterIndex2));
                    const message = new TextDecoder().decode(binaryData.subarray(delimiterIndex2 + 1, delimiterIndex3));
                    const sender_username = new TextDecoder().decode(binaryData.subarray(delimiterIndex3 + 1, delimiterIndex4));
                    const public_key = new TextDecoder().decode(binaryData.subarray(delimiterIndex4 + 1, delimiterIndex5));
                    const parsed_public_key = (public_key === 'None') ? null : public_key;
                    const device_id = new TextDecoder().decode(binaryData.subarray(delimiterIndex5 + 1, delimiterIndex6));
                    console.log(public_key);
                    if (sender_username === getActivePerson()) {
                        const actualBinaryData = binaryData.subarray(delimiterIndex6 + 1);

                        console.log(actualBinaryData);

                        await encryption_instance[device_id].setReceiverKey_JWK(public_key);
                        let decrypted_cipher = null;
                        if (message !== '') {
                            decrypted_cipher = await encryption_instance[device_id].recvImage(actualBinaryData, message);
                        } else {
                            decrypted_cipher = await encryption_instance[device_id].recvImage(actualBinaryData, null);
                        }
                        console.log(decrypted_cipher.image_bytes);

                        const imageBlob = new Blob([decrypted_cipher.image_bytes], {type: 'image/webp'});
                        const messageType = sender_username === userUsername ? 'you' : getActivePerson();
                        if (message !== '') {
                            if (parsed_public_key) {
                                // await encryption.setReceiverKey_JWK(parsed_public_key);
                                // let text_message = await encryption.recv(message, encryption.receiver_public_key);
                                if (messageType === "you") {
                                    updateImage(imageBlob, null, message_id, null, decrypted_cipher.text_message);
                                } else {
                                    updateImage(imageBlob, getActivePerson(), message_id, null, decrypted_cipher.text_message);
                                }
                            }
                        } else {
                            if (messageType === "you") {
                                updateImage(imageBlob, null, message_id, null, null);
                            } else {
                                updateImage(imageBlob, getActivePerson(), message_id, null, null);
                            }
                        }

                        // Scroll to the bottom
                        var snapUiContainer = document.getElementById('snap-ui-container');
                        snapUiContainer.scrollTop = snapUiContainer.scrollHeight;


                        // Hide the loading icon after receiving a message
                        const loadingIcon = document.getElementById('loading');
                        loadingIcon.style.display = 'none';

                        message_seen(message_id);
                    } else {
                        update_message_status(STATUS_RECEIVED, sender_username);
                    }
                } else if (type === 1) {
                    const message_id = new TextDecoder().decode(binaryData.subarray(delimiterIndex1 + 1, delimiterIndex2));
                    const cipher_text = new TextDecoder().decode(binaryData.subarray(delimiterIndex2 + 1, delimiterIndex3));
                    const AES = new TextDecoder().decode(binaryData.subarray(delimiterIndex3 + 1, delimiterIndex4));
                    const room = new TextDecoder().decode(binaryData.subarray(delimiterIndex4 + 1, delimiterIndex5));

                    if (room === getActiveRoom()) {
                        const actualBinaryData = binaryData.subarray(delimiterIndex5 + 1);

                        let decrypted_cipher = await decryptASYM_Image_Message(actualBinaryData, cipher_text, AES)
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
                        get_device_public_keys(getActivePerson(), getActiveRoom(), data.device_id);
                        for (const device_id in encryption_instance) {
                            if (!data.active_device_ids.includes(device_id)) {
                                delete encryption_instance[device_id];
                            }
                        }
                    } else {
                        if (encryption_instance[data.device_id]) {
                            delete encryption_instance[data.device_id]
                            if (Object.keys(encryption_instance).length === 0) {
                                get_user_public_keys(getActivePerson(), getActiveRoom());
                            }
                        }
                    }
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

// Function to handle sending messages
const sendMessage = async function () {
    if (isWebSocketReady(chatSocket)) {
        const messageInput = document.querySelector('#input');
        let message = messageInput.value.trim();

        if (message !== '' || imageInput.files.length > 0) {
            $('#form-messages').hide();
            const loadingIcon = document.getElementById('loading');
            loadingIcon.style.display = 'inline-block';

            // Check if there is an image selected
            if (imageInput.files.length > 0) {
                const file = imageInput.files[0];
                const img = new Image();
                img.src = URL.createObjectURL(file);

                img.onload = async function () {
                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    canvas.width = img.width;
                    canvas.height = img.height;

                    // Step 1: Reduce Quality
                    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                    canvas.toBlob((webpBlob) => {

                        // // Create a new Blob containing text and binary data
                        // if (encrypted_message) {
                        //     const combinedBlob = new Blob([JSON.stringify({
                        //         message: encrypted_message.cipher,
                        //         storeMessage: storeMessage,
                        //         public_key: encrypted_message.ratchet_key
                        //     }), webpBlob]);
                        //     chatSocket.send(combinedBlob);
                        // } else {
                        //     const combinedBlob = new Blob([JSON.stringify({
                        //         message: encrypted_message,
                        //         storeMessage: storeMessage,
                        //         public_keys: null
                        //     }), webpBlob]);
                        //     chatSocket.send(combinedBlob);
                        // }

                        if (message === '') {
                            imageEncryption_send(webpBlob, null);
                        } else {
                            imageEncryption_send(webpBlob, message);
                        }

                        var imageElement = document.getElementById('selectedImage');
                        imageElement.src = ''; // Reset the source
                        imageInput.value = '';
                        imageInput.type = 'file';

                        bytes_webpBlob = webpBlob;
                        bytes_message = message;
                        updateImageLabelIcon(imageInput)

                        var labelElement = document.getElementById('image_input_label');
                        labelElement.style.display = 'flex';

                        imageElement.style.display = 'none';

                        let current_time = new Date();
                        handleNewMessage(getActivePerson(), current_time, false);
                        update_message_status(STATUS_DELIVERED, getActivePerson());
                    }, 'image/webp', 0.7);
                };
            } else {
                var replyMessageHolder = document.getElementById('reply_message_holder');

                let encrypted_message = await encryption_send(message);
                var containsSnapMessage = replyMessageHolder.querySelector('snap-message') !== null;

                let encrypted_sent_messages = await encryptSentMessage(message);

                if (containsSnapMessage) {
                    const reply_id = replyMessageHolder.querySelector('snap-message').id;

                    chatSocket.send(JSON.stringify({
                        'type': 'message',
                        'message': encrypted_message,
                        'storeMessage': storeMessage,
                        'reply_id': reply_id,
                        'sent_message': encrypted_sent_messages
                    }));
                    sent_reply_id = reply_id;
                    bytes_message = message;
                } else {
                    chatSocket.send(JSON.stringify({
                        'type': 'message',
                        'message': encrypted_message,
                        'storeMessage': storeMessage,
                        'sent_message': encrypted_sent_messages
                    }));
                    bytes_message = message;
                }
            }

            // Scroll to the bottom after sending a message
            var snapUiContainer = document.getElementById('snap-ui-container');
            snapUiContainer.scrollTop = snapUiContainer.scrollHeight;


            messageInput.value = '';
        } else {
            $('#form-messages').html('<div class="alert alert-danger" role="alert">' + "Please type a message" + '</div>');
        }
    }
}

// Event listener for the Enter key press in the input field
document.querySelector('#input').addEventListener('keypress', function (event) {
    if (event.key === 'Enter') {
        sendMessage();
        event.preventDefault(); // Prevents the default Enter key behavior (e.g., new line in textarea)
    }
});

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

const displayImages = function () {
    const imageContainer = document.getElementById('snap-ui-container');

    imageContainer.addEventListener('click', function (event) {
        const imageUrl = getImageUrl(event.target);

        if (imageUrl !== null) {
            const modalElement = document.getElementById('image-viewer');
            modalElement.style.display = 'block';

            const fullImageElement = document.getElementById('full-image');
            fullImageElement.src = imageUrl;
        }
    });

    function getImageUrl(element) {
        // Check if the clicked element is an image or a child of an image
        const isImage = element.tagName === 'IMG' || element.closest('img');

        // If it's an image, return the src, otherwise return null
        return isImage ? element.src : null;
    }

    const closeButtonElement = document.getElementById('close-button');
    closeButtonElement.addEventListener('click', function () {
        // Hide the modal
        const modalElement = document.getElementById('image-viewer');
        modalElement.style.display = 'none';
    });
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
    const heading_name = document.getElementById('heading_name');
    heading_name.innerHTML = `${username}`;
    const newUserStatusSpan = document.createElement('span');
    newUserStatusSpan.className = 'preview';
    newUserStatusSpan.style.fontSize = '14px'; // Set the desired style
    newUserStatusSpan.style.color = 'rgb(217,217,217)'; // Set the desired style
    newUserStatusSpan.style.marginLeft = 8;

    var personElement = document.querySelector(`[data-chat='${username}']`);

    if (typing) {
        newUserStatusSpan.textContent = 'typing';
        update_message_status(STATUS_TYPING, username, false);
    } else {
        if (personElement) {
            newUserStatusSpan.textContent = personElement.getAttribute('status');
            var statusValue = personElement.getAttribute('message_status');
            if (statusValue) {
                var intValue = parseInt(statusValue, 10);
                update_message_status(intValue, username, false);
            } else {
                update_message_status(STATUS_RECEIVED, username, false);
            }
        }
    }
    heading_name.appendChild(newUserStatusSpan);
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
    let roomData = getKeysByRoom(getActiveRoom());
    for (const device_id in publicKeysInfo) {
        if (publicKeysInfo.hasOwnProperty(device_id)) {
            const keysInfo = publicKeysInfo[device_id];

            let encryptionInstance;
            if (roomData.type === 'sender') {
                encryptionInstance = new Alice(room, device_id, keysInfo.version);
            } else if (roomData.type === 'receiver') {
                encryptionInstance = new Bob(room, device_id, keysInfo.version);
            }
            await encryptionInstance.retrieveAndImportKeys();
            await encryptionInstance.x3dh(keysInfo.public_keys);
            await encryptionInstance.initRatchets();
            await encryptionInstance.setReceiverKey(keysInfo.ratchet_public_key);
            encryption_instance[device_id] = encryptionInstance;
        }
    }
}

async function initialize_single_key(room, keysInfo, device_id) {
    let roomData = getKeysByRoom(getActiveRoom());
    let encryptionInstance;
    if (roomData.type === 'sender') {
        encryptionInstance = new Alice(room, device_id);
    } else if (roomData.type === 'receiver') {
        encryptionInstance = new Bob(room, device_id);
    }
    await encryptionInstance.retrieveAndImportKeys();
    await encryptionInstance.x3dh(keysInfo.public_keys);
    await encryptionInstance.initRatchets();
    await encryptionInstance.setReceiverKey(keysInfo.ratchet_public_key);
    encryption_instance[device_id] = encryptionInstance;
}

async function initialize_ratchet_encryption_temp(room, keysInfo, ratchet_key, device_id) {
    let roomData = getKeysByRoom(getActiveRoom());
    let encryptionInstance;

    if (roomData) {
        if (roomData.type === 'sender') {
            encryptionInstance = new Alice(room, device_id);
        } else if (roomData.type === 'receiver') {
            encryptionInstance = new Bob(room, device_id);
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

    // Use Object.values to get an array of instances
    const instances = Object.values(encryption_instance);

    // Use Promise.all to execute the send method for each instance
    const sendPromises = instances.map(async (instance) => {
        responses[instance.device_id] = await instance.send(message);
    });

    // Wait for all sendPromises to resolve
    await Promise.all(sendPromises);

    // Now 'responses' contains the responses for each device_id
    return JSON.stringify(responses);
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
                const messageObject = {
                    type: 0,
                    message: encryptedMessage.cipher,
                    storeMessage: storeMessage,
                    public_key: encryptedMessage.ratchet_key,
                    device_id: instance.device_id,
                    message_id: messageId,
                    flag: flag,
                    key_version: encryptedMessage.key_version,
                };
                const combinedBlob = new Blob([JSON.stringify(messageObject), encryptedMessage.bytes_cipher]);
                chatSocket.send(combinedBlob);
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
                    type: 1,
                    message: encryptedMessage.ciphertext,
                    AES: encryptedMessage.AES,
                    device_id: instance.device_id,
                    message_id: messageId,
                };
                const combinedBlob = new Blob([JSON.stringify(messageObject), encryptedMessage.cipherbytes]);
                chatSocket.send(combinedBlob);
                }
            })
            .catch(error => {
                console.error('Error encrypting message:', error);
            });
    });
}

async function decryptSentMessage(cipher, aes) {
    return await decryptASYM_Message(cipher, aes);
}