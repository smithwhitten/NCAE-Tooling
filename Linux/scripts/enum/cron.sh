
#!/bin/bash

printAll() {
    # print all system cronjobs
    echo "################ All System Cronjobs  ################"
    ls -l /etc/cron.d/

    # print all user cronjobs
    echo "################ All User Cronjobs  ################"
    for user in $(cut -f1 -d: /etc/passwd); do
        echo "---[ USER: $user ]---"
        crontab -l -u "$user" 2>/dev/null
    done

    # All hourly cronjobs
    echo "################ All Hourly Cronjobs  ################"
    ls -l /etc/cron.hourly/

    # All Daily cronjobs
    echo "################ All Daily Cronjobs  ################"
    ls -l /etc/cron.daily/

    # All Weekly cronjobs
    echo "################ All Weekly Cronjobs  ################"
    ls -l /etc/cron.weekly/

    # All Monthly cronjobs
    echo "################ All Monthly Cronjobs  ################"
    ls -l /etc/cron.monthly/
}

Addjob() {
    read -r -p "What command? " CRON_CMD
    read -r -p "What time frame? (m h dom mon dow) - use '*' if unused: " CRON_TIME
    CRON_JOB="$CRON_TIME $CRON_CMD"

    (crontab -l 2>/dev/null | grep -v -F "$CRON_CMD"; echo "$CRON_JOB") | crontab -
}

Removejob() {

    echo "Available users:"
    cut -f1 -d: /etc/passwd

    read -r -p "Enter username whose cron job you want to delete: " TARGET_USER

    if ! id "$TARGET_USER" >/dev/null 2>&1; then
        echo "User does not exist."
        return
    fi

    if ! crontab -u "$TARGET_USER" -l >/dev/null 2>&1; then
        echo "No crontab found for $TARGET_USER."
        return
    fi

    echo
    echo "Current cron jobs for $TARGET_USER:"
    crontab -u "$TARGET_USER" -l
    echo

    read -r -p "Enter text to identify the cron job to delete: " CRON_MATCH

    if [ -z "$CRON_MATCH" ]; then
        echo "No input provided. Exiting."
        return
    fi

    crontab -u "$TARGET_USER" -l | grep -F -v -- "$CRON_MATCH" | crontab -u "$TARGET_USER" -

    echo "Cron job(s) containing '$CRON_MATCH' removed for $TARGET_USER (if any existed)."
}


printAll

USER_CHOICE=0

while [ "$USER_CHOICE" != "4" ]; do
    echo
    echo "1.) Print"
    echo "2.) Add"
    echo "3.) Remove"
    echo "4.) Exit"
    read -r -p "What number? " USER_CHOICE

    if [ "$USER_CHOICE" = "1" ]; then
        printAll
    elif [ "$USER_CHOICE" = "2" ]; then
        Addjob
    elif [ "$USER_CHOICE" = "3" ]; then
        Removejob
    elif [ "$USER_CHOICE" = "4" ]; then
        exit 0
    else
        echo "Invalid option"
    fi
done

