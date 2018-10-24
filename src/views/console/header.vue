<template>
    <div>
        <div class="logo"></div>
        <div class="header-right">
            this is from Header, data is {{ data }}
            <Avatar :style="{background:supervisor_status_color}" :icon="supervisor_status_icon" size="small"/>
            <Button size="large" type="primary" @click="handler">Header Button</Button>
        </div>
    </div>
</template>
<script>
    export default {
        props: ['data'],
        data: function () {
            return {
                supervisor_status_color: 'Orange',
                supervisor_status_icon: 'md-warning'
            }
        },
        created: function () {
            this.refresh_supervisor_status()
        },
        methods: {
            refresh_supervisor_status () {
                this.$http.post('/supervisor', '{"type":"ping"}').then(function (response) {
                    if (response.data.status == 'OK') {
                        if (response.data.data == 'pong') {
                            this.supervisor_status_color = 'LimeGreen'
                            this.supervisor_status_icon = 'md-play'
                        } else {
                            this.supervisor_status_color = 'Orange'
                            this.supervisor_status_icon = 'md-warning'
                        }
                    } else {
                        this.supervisor_status_color = 'Orange'
                        this.supervisor_status_icon = 'md-warning'
                    }
                }, function (response) {
                    this.supervisor_status_color = 'Red'
                    this.supervisor_status_icon = 'md-close'
                })
                setTimeout(() => { this.refresh_supervisor_status() }, 5000);
            },
            handler () {
                this.$http.post('/supervisor', '{"type":"test"}').then(function (response) {
                    console.log(JSON.stringify(response.data))
                }, function (response) {
                    // something error.
                })
                //this.$emit('set_sider_data', 'sider data from header');
                //this.$emit('set_content_data', 'content data from header');
                //this.$Modal.info({
                //    title: 'nihao title',
                //    content: 'nihao content'
                //});
            }
        }
    }
</script>
