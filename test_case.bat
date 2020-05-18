python test_client.py --url http://localhost:8899 --token user1token --num 100 addtoken
python test_client.py --url http://localhost:8899 --token user2token --num 200 addtoken
python test_client.py --url http://localhost:8899 --token user3token --num 300 addtoken
python test_client.py --url http://localhost:8899 --token user4token --num 400 addtoken

python test_client.py --url http://localhost:8899 --token user1token --id user1 register
python test_client.py --url http://localhost:8899 --token user2token --id user2 register
python test_client.py --url http://localhost:8899 --token user3token --id user3 register
python test_client.py --url http://localhost:8899 --token user4token --id user4 register

python test_client.py --url http://localhost:8899 --id user4 --file some.pdf adddocument

python test_client.py --url http://localhost:8899 --id user1 --name some.pdf sign
python test_client.py --url http://localhost:8899 --id user2 --name some.pdf sign 
python test_client.py --url http://localhost:8899 --id user3 --name some.pdf sign 
python test_client.py --url http://localhost:8899 --id user4 --name some.pdf sign

python test_client.py --url http://localhost:8899 --id user2 --name some.pdf validate

python test_client.py --url http://localhost:8899 --id user3 allsigned