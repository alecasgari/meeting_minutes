// static/js/main.js

// Wait for the HTML document to be fully loaded before running the script
document.addEventListener('DOMContentLoaded', function() {

    // --- Dynamic Agenda Items ---

    // Find the button for adding new agenda items
    const addAgendaItemButton = document.getElementById('add-agenda-item');
    // Find the container where new agenda items will be added
    const agendaItemsContainer = document.getElementById('agenda-items-container');

    // Check if the button and container actually exist on the current page
    if (addAgendaItemButton && agendaItemsContainer) {

        // --- Add Item Logic ---
        addAgendaItemButton.addEventListener('click', function() {
            // Create a new div to hold the input and remove button
            const newItemDiv = document.createElement('div');
            newItemDiv.classList.add('agenda-item'); // Add the same class for consistency
            newItemDiv.style.marginBottom = '5px'; // Add some spacing

            // Create the new text input field
            const newInput = document.createElement('input');
            newInput.type = 'text';
            // IMPORTANT: The name must match the FieldList name in WTForms
            newInput.name = 'agenda_items';
            newInput.size = 50; // Optional: set size
            newInput.classList.add('form-control'); // Optional: add class for styling

            // Create the new remove button
            const removeButton = document.createElement('button');
            removeButton.type = 'button'; // Prevent form submission
            removeButton.textContent = '-'; // Text on the button
            removeButton.classList.add('remove-agenda-item'); // Class to identify remove buttons
            removeButton.style.marginLeft = '5px'; // Add some space

            // Append the input and remove button to the new div
            newItemDiv.appendChild(newInput);
            newItemDiv.appendChild(removeButton);

            // Append the new div (with input and button) to the main container
            agendaItemsContainer.appendChild(newItemDiv);
        });

        // --- Remove Item Logic (using Event Delegation) ---
        // Add ONE event listener to the container, not to each button
        agendaItemsContainer.addEventListener('click', function(event) {
            // Check if the clicked element is actually a remove button
            if (event.target.classList.contains('remove-agenda-item')) {
                // Find the parent div (.agenda-item) of the clicked button
                const itemToRemove = event.target.closest('.agenda-item');
                if (itemToRemove) {
                    // Remove the entire div (including input and button)
                    itemToRemove.remove();
                }
            }
        });
    }

    // --- Add logic for other dynamic fields (like attendees) here later ---

}); // End of DOMContentLoaded listener