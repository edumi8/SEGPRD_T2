FROM python

WORKDIR /usr/src/app

# Copying requirements and installing dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copying the rest of the application
COPY . .

# Setting the default value of the level argument
ARG level=root

# Set environment variable for the entrypoint script
ENV ENVIRONMENT=$level

# Running commands based on the level argument
RUN if [ "$level" = "root" ]; then \
    echo "Running in production environment"; \
    elif [ "$level" = "services" ]; then \
    echo "Running in development environment"; \
    else \
    echo "users CA"; \
    fi

# Print the environment variable to ensure it's set
RUN echo "Environment is: $ENVIRONMENT"

ENTRYPOINT [ "./entrypoint.sh" ]
