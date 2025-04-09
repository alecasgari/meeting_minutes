// static/js/main.js - Final Version with all dynamic fields

document.addEventListener('DOMContentLoaded', function() {

    // --- Dynamic Agenda Items ---
    const addAgendaItemButton = document.getElementById('add-agenda-item');
    const agendaItemsContainer = document.getElementById('agenda-items-container');
    if (addAgendaItemButton && agendaItemsContainer) {
        addAgendaItemButton.addEventListener('click', function() {
            const currentItemCount = agendaItemsContainer.children.length;
            const newItemDiv = document.createElement('div');
            newItemDiv.classList.add('agenda-item');
            newItemDiv.style.marginBottom = '5px';
            const newInput = document.createElement('input');
            newInput.type = 'text';
            newInput.name = `agenda_items-${currentItemCount}`;
            newInput.id = `agenda_items-${currentItemCount}`;
            newInput.required = true;
            newInput.size = 50;
            newInput.classList.add('form-control');
            const removeButton = document.createElement('button');
            removeButton.type = 'button';
            removeButton.textContent = '-';
            removeButton.classList.add('remove-agenda-item');
            removeButton.style.marginLeft = '5px';
            newItemDiv.appendChild(newInput);
            newItemDiv.appendChild(removeButton);
            agendaItemsContainer.appendChild(newItemDiv);
        });
        agendaItemsContainer.addEventListener('click', function(event) {
            if (event.target.classList.contains('remove-agenda-item')) {
                const itemToRemove = event.target.closest('.agenda-item');
                if (itemToRemove) { itemToRemove.remove(); }
            }
        });
    }

    // --- Dynamic Attendees ---
    const addAttendeeButton = document.getElementById('add-attendee-button');
    const attendeesContainer = document.getElementById('attendees-container');
    if (addAttendeeButton && attendeesContainer) {
        addAttendeeButton.addEventListener('click', function() {
            const currentItemCount = attendeesContainer.children.length;
            const newItemDiv = document.createElement('div');
            newItemDiv.classList.add('attendee-item');
            newItemDiv.style.marginBottom = '5px';
            const newInput = document.createElement('input');
            newInput.type = 'text';
            newInput.name = `attendees-${currentItemCount}`;
            newInput.id = `attendees-${currentItemCount}`;
            newInput.size = 50;
            newInput.classList.add('form-control');
            const removeButton = document.createElement('button');
            removeButton.type = 'button';
            removeButton.textContent = '-';
            removeButton.classList.add('remove-attendee-item');
            removeButton.style.marginLeft = '5px';
            newItemDiv.appendChild(newInput);
            newItemDiv.appendChild(removeButton);
            attendeesContainer.appendChild(newItemDiv);
        });
        attendeesContainer.addEventListener('click', function(event) {
            if (event.target.classList.contains('remove-attendee-item')) {
                const itemToRemove = event.target.closest('.attendee-item');
                if (itemToRemove) { itemToRemove.remove(); }
            }
        });
    }

    // --- Dynamic Action Items ---
    const addActionButton = document.getElementById('add-action-item-button');
    const actionItemsContainer = document.getElementById('action-items-container');
    if (addActionButton && actionItemsContainer) {
        addActionButton.addEventListener('click', function() {
            const currentItemCount = actionItemsContainer.children.length;
            const newItemDiv = document.createElement('div');
            newItemDiv.classList.add('action-item-group');
            newItemDiv.style.border = '1px solid #eee';
            newItemDiv.style.padding = '10px';
            newItemDiv.style.marginBottom = '10px';
            newItemDiv.style.borderRadius = '4px';

            const descDiv = document.createElement('div');
            descDiv.style.marginBottom = '5px';
            const descLabel = document.createElement('label');
            descLabel.setAttribute('for', `action_items-${currentItemCount}-description`);
            descLabel.textContent = 'Description';
            const descInput = document.createElement('textarea');
            descInput.name = `action_items-${currentItemCount}-description`;
            descInput.id = `action_items-${currentItemCount}-description`;
            descInput.rows = 2;
            descInput.classList.add('form-control');
            descInput.style.width = '95%';
            descDiv.appendChild(descLabel);
            descDiv.appendChild(document.createElement('br'));
            descDiv.appendChild(descInput);
            newItemDiv.appendChild(descDiv);

            const assignedDiv = document.createElement('div');
            assignedDiv.style.marginBottom = '5px';
            assignedDiv.style.display = 'inline-block';
            assignedDiv.style.marginRight = '10px';
            const assignedLabel = document.createElement('label');
            assignedLabel.setAttribute('for', `action_items-${currentItemCount}-assigned_to`);
            assignedLabel.textContent = 'Assigned To';
            const assignedInput = document.createElement('input');
            assignedInput.type = 'text';
            assignedInput.name = `action_items-${currentItemCount}-assigned_to`;
            assignedInput.id = `action_items-${currentItemCount}-assigned_to`;
            assignedInput.size = 20;
            assignedInput.classList.add('form-control');
            assignedDiv.appendChild(assignedLabel);
            assignedDiv.appendChild(document.createElement('br'));
            assignedDiv.appendChild(assignedInput);
            newItemDiv.appendChild(assignedDiv);

            const deadlineDiv = document.createElement('div');
            deadlineDiv.style.marginBottom = '5px';
            deadlineDiv.style.display = 'inline-block';
            const deadlineLabel = document.createElement('label');
            deadlineLabel.setAttribute('for', `action_items-${currentItemCount}-deadline`);
            deadlineLabel.textContent = 'Deadline';
            const deadlineInput = document.createElement('input');
            deadlineInput.type = 'date';
            deadlineInput.name = `action_items-${currentItemCount}-deadline`;
            deadlineInput.id = `action_items-${currentItemCount}-deadline`;
            deadlineInput.classList.add('form-control');
            deadlineDiv.appendChild(deadlineLabel);
            deadlineDiv.appendChild(document.createElement('br'));
            deadlineDiv.appendChild(deadlineInput);
            newItemDiv.appendChild(deadlineDiv);

            const removeButton = document.createElement('button');
            removeButton.type = 'button';
            removeButton.textContent = 'Remove Action';
            removeButton.classList.add('remove-action-item');
            removeButton.style.marginLeft = '10px';
            removeButton.style.color = 'red';
            removeButton.style.border = 'none';
            removeButton.style.background = 'none';
            removeButton.style.cursor = 'pointer';
            removeButton.style.verticalAlign = 'bottom';
            newItemDiv.appendChild(removeButton);

            actionItemsContainer.appendChild(newItemDiv);
        });

        actionItemsContainer.addEventListener('click', function(event) {
            if (event.target.classList.contains('remove-action-item')) {
                const itemToRemove = event.target.closest('.action-item-group');
                if (itemToRemove) {
                    itemToRemove.remove();
                }
            }
        });
    }

}); // End of DOMContentLoaded listener