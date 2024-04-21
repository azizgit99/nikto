# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies
RUN apt-get update
RUN apt-get install -y perl wget unzip
RUN wget https://github.com/sullo/nikto/archive/master.zip
RUN unzip master.zip
RUN mv nikto-master nikto
RUN rm master.zip
RUN apt-get purge -y --auto-remove wget


# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Define environment variable
ENV NIKTO_PATH=/app/nikto/program/nikto.pl

# Run engine.py when the container launches
CMD ["python", "nikto.py"]
