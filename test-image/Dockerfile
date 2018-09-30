FROM jwt-nginx

# Get nginx ready to run
COPY nginx /etc/nginx

EXPOSE 8000

STOPSIGNAL SIGTERM

CMD ["nginx", "-g", "daemon off;"]
