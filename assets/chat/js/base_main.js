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
        saveTextElement.setAttribute('disabled', true);
        saveTextElement.style.pointerEvents = 'none';
        saveTextElement.style.opacity = '0.5'
    } else {
        saveTextElement.setAttribute('disabled', false);
        saveTextElement.style.pointerEvents = 'auto';
        saveTextElement.style.opacity = '1';
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
            snapMessage.appendChild(imageElement);
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
        saveMessageToServer(message_id, true, reply_id || null)
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

function saveMessageToServer(message_id, isSave, reply_id) {
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
        chatSocket.send(JSON.stringify({
            'type': 'save_message',
            'save_message': isSave,
            'message_id': message_id,
            'message': message,
            'reply_id': reply_id || null,
            'sender': sender,
            'receiver': receiver,
        }));
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
    const snapMessages = container.querySelectorAll('snap-message');

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

    // Access the shadow DOM of the snap-message element
    const shadowRoot = actualFirstElement.shadowRoot;

    // Check if the shadow DOM is available
    if (shadowRoot) {
        // Retrieve the value of the 'additional-text' attribute inside the shadow DOM
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
function handleNewMessage(username, message, timestamp) {
    // Find the person element by username
    var personElement = document.querySelector(`[data-chat='${username}']`);

    // Update the preview message
    var previewElement = personElement.querySelector('.preview');
    previewElement.textContent = message;
    previewElement.style.color = "#00ff92";


    const date = new Date(timestamp);
    const time = date.toLocaleTimeString('en-US', {hour: 'numeric', minute: 'numeric', hour12: true});
    var timeElement = personElement.querySelector('.time');
    timeElement.textContent = time;
    timeElement.style.color = "#00ff92";
}

// handle new message

// Section: Core message
const chatContainer = document.getElementById('chat_container');
let chatSocket = null;

let bytes_webpBlob = null;
let bytes_message = null;

function close_chat() {
    document.getElementById('chat_parent_container').style.display = 'none';
    document.getElementById('left_bar').style.display = 'block';
}

function load_chat(userName) {

    if (window.innerWidth <= 768) {
        document.getElementById('chat_parent_container').style.display = 'block';
        document.getElementById('left_bar').style.display = 'none';
        document.getElementById('container_image').style.display = 'none';
    }

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
    timeElement.style.color = '#8a8a8a';

    if (userName) {
        if (chatSocket) {
            chatSocket.close();
            chatSocket.onmessage = null;
        }
        chatSocket = null;
        chatSocket = new WebSocket(
            `${protocol}://` + window.location.host + `/ws/chat/?sender_username=${userUsername}&receiver_username=${userName}`
        );
        chatSocket.binaryType = 'blob'
        initialize_socket();
    }
    $.ajax({
        type: 'POST',
        url: `/chat/load/messages/${userName}/`,  // Adjust the URL based on your Django URL configuration
        dataType: 'json',
        success: function (response) {
            if (response.status === 'success') {
                // Handle the received messages
                var messages = JSON.parse(response.data);
                load_chat_message(messages);
            } else {
                console.error('Error loading messages:', response.message);
            }
        },
        error: function (error) {
            console.error('Error loading messages:', error);
        }
    });
}

function load_chat_message(messages) {
    var inputBoxContainer = document.getElementById('input-box-container');
    inputBoxContainer.style.display = 'flex';

    const snapUiContainer = document.getElementById('snap-ui-container');
    snapUiContainer.addEventListener('mouseover', handleHover);
    snapUiContainer.addEventListener('mouseout', handleHoverEnd);

    var image_container = document.getElementById('container_image');
    image_container.style.display = "none";

    // Group messages by date
    const messagesByDate = groupMessagesByDate(messages);

    // Check if there are no messages at all
    if (Object.keys(messagesByDate).length === 0) {
        const currentDate = new Date();
        const formattedCurrentDate = currentDate.toLocaleDateString();
        addSnapNotice(formattedCurrentDate);
    }

    let newMessage = true;

    // Loop through the grouped messages and append them to the chat container
    for (const [date, messagesInDate] of Object.entries(messagesByDate)) {
        let dateAppended = false;  // Flag to track whether the date has been appended

        const messagesForDate = messagesInDate.sort((a, b) => a.message_id - b.message_id);

        messagesForDate.forEach(function (message, index) {
            // Determine if the message is sent or received based on the sender
            const messageType = message.sender__username === userUsername ? 'you' : getActivePerson();

            // Display the date section only once for the first message in the group
            if (index === 0 && !dateAppended) {
                // Append the date
                addSnapNotice(date);
                dateAppended = true;  // Set the flag to true once the date is appended
            }

            // Display the message with the appropriate indicator
            const save = message.temp__username === null
            if (newMessage) {
                if (message.temp__username === userUsername) {
                    addSnapNotice(null, "New message")
                }
                newMessage = false;
            }
            if (messageType === 'you') {
                if (message.reply_id !== null) {
                    addSnapMessage(message.message_id, message.message, null, save, null, message.reply_id, message.timestamp);
                } else {
                    addSnapMessage(message.message_id, message.message, null, save, null, null, message.timestamp);
                }
            } else {
                if (message.reply_id !== null) {
                    addSnapMessage(message.message_id, message.message, getActivePerson(), save, null, message.reply_id, message.timestamp);
                } else {
                    addSnapMessage(message.message_id, message.message, getActivePerson(), save, null, null, message.timestamp);
                }
            }
        });
    }


    // Scroll to the bottom
    var header_content = document.getElementById('header_content');
    header_content.style.display = 'inline-block';
    chatContainer.scrollTop = chatContainer.scrollHeight;
}

function getActivePerson() {
    var activePersonElement = document.querySelector('.person.active');

    if (activePersonElement) {
        return activePersonElement.getAttribute('data-chat');
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
    displayImages();
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

function initialize_socket() {
    chatSocket.onmessage = async function (e) {
        if (e.data instanceof Blob) {
            const reader = new FileReader();

            reader.onload = function (event) {
                const binaryData = new Uint8Array(event.target.result);

                // Find delimiter indices
                const delimiterIndex1 = binaryData.indexOf('\n'.charCodeAt(0));
                const delimiterIndex2 = binaryData.indexOf('\n'.charCodeAt(0), delimiterIndex1 + 1);

                // Extract text data
                const message_id = new TextDecoder().decode(binaryData.subarray(0, delimiterIndex1));
                const message = new TextDecoder().decode(binaryData.subarray(delimiterIndex1 + 1, delimiterIndex2));
                const sender_username = new TextDecoder().decode(binaryData.subarray(delimiterIndex2 + 1));

                // Find the starting point of the image data
                const startIndex = binaryData.indexOf('RIFF'.charCodeAt(0));
                // Extract binary data
                const actualBinaryData = binaryData.subarray(startIndex);

                const imageBlob = new Blob([actualBinaryData], {type: 'image/webp'});

                const messageType = sender_username === userUsername ? 'you' : getActivePerson();

                // Display the message with the appropriate indicator

                if (messageType === "you") {
                    updateImage(imageBlob, null, message_id);
                } else {
                    updateImage(imageBlob, getActivePerson(), message_id);
                }

                if (message !== '') {

                    if (messageType === "you") {
                        addSnapMessage(message_id, message, null, null, null, null)
                    } else {
                        addSnapMessage(message_id, message, getActivePerson(), null, null, null)
                    }
                }

                // Scroll to the bottom
                var snapUiContainer = document.getElementById('snap-ui-container');
                snapUiContainer.scrollTop = snapUiContainer.scrollHeight;


                // Hide the loading icon after receiving a message
                const loadingIcon = document.getElementById('loading');
                loadingIcon.style.display = 'none';
            };

            // Read the entire e.data as ArrayBuffer
            reader.readAsArrayBuffer(e.data);
        } else {
            const data = JSON.parse(e.data);

            if (data.type === 'user_status') {
                // Handle user status update, for example, update a user list
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
                }
            } else if (data.type === 'message_sent') {
                if (data.data_type === 'bytes') {
                    updateImage(bytes_webpBlob, null, data.message_id)
                    updateSentMessage(bytes_message, data.message_id);
                    bytes_webpBlob = null;
                    bytes_message = null;
                }
                const loadingIcon = document.getElementById('loading');
                loadingIcon.style.display = 'none';
            } else if (data.type === 'save_message') {
                const message_element = getMessageElementById(data.message_id)
                if (message_element) {
                    if (data.save_message) {
                        message_element.element.setAttribute('saved', '');
                    } else {
                        message_element.element.removeAttribute('saved');
                    }
                }
            } else if (data.type === 'delete_message') {
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
            } else if (data.type === 'new_message_background') {
                handleNewMessage(data.sender_username, data.message, data.timestamp);
            } else {
                // Determine if the message is sent or received based on the sender
                const messageType = data.sender_username === userUsername ? 'you' : getActivePerson();

                // Display the message with the appropriate indicator
                if (messageType === "you") {
                    addSnapMessage(data.message_id, data.message, null, null, null, data.reply_id || null)
                } else {
                    addSnapMessage(data.message_id, data.message, getActivePerson(), null, null, data.reply_id || null)
                }

                // Scroll to the bottom
                var snapUiContainer = document.getElementById('snap-ui-container');
                snapUiContainer.scrollTop = snapUiContainer.scrollHeight;


                // Hide the loading icon after receiving a message
                const loadingIcon = document.getElementById('loading');
                loadingIcon.style.display = 'none';
            }
        }
    }
}

// Function to handle sending messages
const sendMessage = function () {
    const messageInput = document.querySelector('#input');
    const message = messageInput.value.trim();

    if (message !== '' || imageInput.files.length > 0) {
        $('#form-messages').hide();
        const loadingIcon = document.getElementById('loading');
        loadingIcon.style.display = 'inline-block';

        const storeCheckbox = document.getElementById('storeCheckbox');
        const storeMessage = storeCheckbox.checked;

        // Check if there is an image selected
        if (imageInput.files.length > 0) {
            const file = imageInput.files[0];
            const img = new Image();
            img.src = URL.createObjectURL(file);

            img.onload = function () {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = img.width;
                canvas.height = img.height;

                // Step 1: Reduce Quality
                ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                canvas.toBlob((webpBlob) => {
                    // Send the WebP image data (webpBlob) to the server

                    // Create a new Blob containing text and binary data
                    const combinedBlob = new Blob([JSON.stringify({
                        message: message,
                        storeMessage: storeMessage,
                    }), webpBlob]);
                    chatSocket.send(combinedBlob);

                    var imageElement = document.getElementById('selectedImage');
                    imageElement.src = ''; // Reset the source
                    imageInput.value = '';
                    imageInput.type = 'file';

                    bytes_webpBlob = webpBlob;
                    bytes_message = message;
                    updateImageLabelIcon(imageInput)

                    var labelElement = document.getElementById('image_input_label');
                    labelElement.style.display = 'block';

                    // Reset image
                    var imageElement = document.getElementById('selectedImage');
                    imageElement.style.display = 'none';
                }, 'image/webp', 0.7); // Adjust quality as needed
            };
        } else {
            var replyMessageHolder = document.getElementById('reply_message_holder');

            var containsSnapMessage = replyMessageHolder.querySelector('snap-message') !== null;

            if (containsSnapMessage) {
                const reply_id = replyMessageHolder.querySelector('snap-message').id;
                // Send only the message if no image is selected
                chatSocket.send(JSON.stringify({
                    'type': 'reply_message',
                    'message': message,
                    'storeMessage': storeMessage,
                    'reply_id': reply_id,
                }));
            } else {
                // Send only the message if no image is selected
                chatSocket.send(JSON.stringify({
                    'type': 'message',
                    'message': message,
                    'storeMessage': storeMessage,
                }));
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

// Event listener for the Enter key press in the input field
document.querySelector('#input').addEventListener('keypress', function (event) {
    if (event.key === 'Enter') {
        sendMessage();
        event.preventDefault(); // Prevents the default Enter key behavior (e.g., new line in textarea)
    }
});

const updateSentMessage = function (message, message_id, reply_id = null) {

    if (message !== '') {
        addSnapMessage(message_id, message, null, null, null, reply_id || null);
    }

    // Scroll to the bottom
    var snapUiContainer = document.getElementById('snap-ui-container');
    snapUiContainer.scrollTop = snapUiContainer.scrollHeight;

    if (reply_id) {
        closeReplyMessageHolder();
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
        const date = new Date(timestamp);
        const time = date.toLocaleTimeString('en-US', {hour: 'numeric', minute: 'numeric', hour12: true});
        snapMessage.setAttribute('timestamp', time);
    } else {
        const date = new Date(message_id);
        const time = date.toLocaleTimeString('en-US', {hour: 'numeric', minute: 'numeric', hour12: true});
        snapMessage.setAttribute('timestamp', time);
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
        snapMessage.appendChild(imageElement);

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
                clonedElement.id = result.element.id;
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
                clonedElement.id = result.element.id;

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
        const dateString = createMessageDateString(date);
        snap_notice.textContent = dateString;
    }

    if (message) {
        snap_notice.textContent = message;
    }
    snapUiContainer.appendChild(snap_notice);
}

const updateImage = function (image, from, message_id, input) {
    // Create an object URL from the Blob
    const imageUrl = URL.createObjectURL(image);
    if (from) {
        addSnapMessage(message_id, null, from, null, imageUrl, null)
    } else {
        addSnapMessage(message_id, null, null, null, imageUrl, null)
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
            document.getElementById('image_input_label').style.display = 'block';
            document.getElementById('selectedImage').style.display = 'none';
        }
    }
}