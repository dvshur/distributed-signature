git pull origin aggsig-server;
docker build -t distributed-signature .;
img_id=$(docker ps --filter="ancestor:distributed-signature");
echo "Stopping image "$img_id;
docket stop $img_id;
docker run -p 8080:8080 --restart=always -d distributed-signature
echo "Done";