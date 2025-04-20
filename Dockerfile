# Use an official lightweight Python image as a parent image
FROM python:3.11-slim

# Set environment variables
# Prevents Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1
# Default port, Cloud Run will override this
ENV PORT=8080

# Set the working directory in the container
WORKDIR /app

# Copy just the requirements first to leverage Docker cache
COPY requirements.txt requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Inform Docker that the container listens on the specified port
EXPOSE 8080

# Command to run the application using Gunicorn
# Use the PORT environment variable provided by Cloud Run / set by ENV
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]