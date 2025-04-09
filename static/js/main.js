document.addEventListener('DOMContentLoaded', function() {
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
                if (itemToRemove) {
                    itemToRemove.remove();
                }
            }
        });
    }
});