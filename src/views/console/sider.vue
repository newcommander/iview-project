<template>
    <div class="sider-view">
        <Menu theme="dark" active-name="content-status" width="auto" @on-select="MenuSelected">
            <MenuItem name="content-status">
                <Icon size="24" type="md-speedometer" />
                Status
            </MenuItem>
            <MenuItem name="content-configuration">
                <Icon size="24" type="md-settings" />
                Configuration
            </MenuItem>
            <MenuItem name="content-accounts">
                <Icon size="24" type="md-contacts" />
                Accounts
            </MenuItem>
            <MenuItem name="content-router">
                <Icon size="24" type="md-list" />
                Router
            </MenuItem>
        </Menu>
        this is from Sider, data is {{ message }}
    </div>
</template>
<script>
    export default {
        props: ['data'],
        data: function () {
            return {
                message: this.data
            }
        },
        methods: {
            MenuSelected: function (value) {
                this.message = value;
                this.$emit('set_content_data', value);
            }
        }
    }
</script>
