migrate-kratos:
	kratos -c kratos/config.yml migrate sql -e --yes

up:
	supervisord

update:
	superisorctl update
