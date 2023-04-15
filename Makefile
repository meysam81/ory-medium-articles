migrate-kratos:
	kratos -c kratos/config.yml migrate sql -e --yes

up-kratos:
	kratos -c kratos/config.yml serve --dev
